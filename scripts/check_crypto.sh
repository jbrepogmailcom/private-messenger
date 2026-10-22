#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -x .work-crypto/cargo/bin/cargo ]]; then
  export CARGO_HOME="$PWD/.work-crypto/cargo"
  export RUSTUP_HOME="$PWD/.work-crypto/rustup"
  export PATH="$CARGO_HOME/bin:$PATH"
fi
if [[ -x .work-crypto/toolchain/protoc/bin/protoc ]]; then
  export PROTOC="$PWD/.work-crypto/toolchain/protoc/bin/protoc"
fi
if [[ -x .work-crypto/audit/bin/cargo-audit ]]; then
  export PATH="$PWD/.work-crypto/audit/bin:$PATH"
fi
export PYO3_PYTHON="$PWD/.venv/bin/python"
cargo fmt --manifest-path native/Cargo.toml -- --check
cargo clippy --locked --manifest-path native/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path native/Cargo.toml --test post_quantum
# Requires an independently installed cargo-audit; missing audit tool fails the check.
cargo audit --file native/Cargo.lock

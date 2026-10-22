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
export PYO3_PYTHON="$PWD/.venv/bin/python"
cargo build --release --locked --manifest-path native/Cargo.toml
.venv/bin/python - <<'PY'
import os
import shutil
from pathlib import Path

source = Path('native/target/release/lib_crypto_native.so')
target = Path('src/private_messenger/_crypto_native.abi3.so')
temporary = target.with_name('.crypto-native-building')
shutil.copyfile(source, temporary)
temporary.chmod(0o600)
os.replace(temporary, target)
print('Built pinned native crypto backend.')
PY

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export PYTHONHASHSEED=0
export TZ=UTC
export LC_ALL=C.UTF-8
.venv/bin/python -m build --wheel --sdist "$@"

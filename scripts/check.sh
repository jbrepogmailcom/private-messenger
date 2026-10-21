#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/bandit -q -r src
.venv/bin/pytest -q
.venv/bin/pip-audit -r requirements.lock --disable-pip

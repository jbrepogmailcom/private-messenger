#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
.venv/bin/python -c 'from private_messenger.crypto.backend import operation; operation("metadata")'
.venv/bin/ruff check src tests scripts setup.py
.venv/bin/ruff format --check src tests scripts setup.py
.venv/bin/bandit -q -r src
.venv/bin/pytest -q
.venv/bin/pip-audit -r requirements.lock --disable-pip

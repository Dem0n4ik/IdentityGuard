#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
export PYTHONPATH=backend
exec uv run --locked python -m app.stratus fetch "$@"

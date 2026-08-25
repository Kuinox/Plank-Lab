#!/usr/bin/env bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
exec uv run --with numpy --with pyarrow --with duckdb --with thriftpy2 python pqmin/bootstrap.py "$@"

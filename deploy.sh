#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 0 ]; then
    echo "Usage: $0" >&2
    exit 1
fi

PROJECT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
exec "$PROJECT_DIR/run_pipeline_v7.sh"

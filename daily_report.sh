#!/usr/bin/env bash
set -euo pipefail
umask 077
PROJECT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$PROJECT_DIR/report_config.py" \
    --config "${THESIS_REPORT_CONFIG:-$PROJECT_DIR/config/reporting.json}" \
    --previous-day

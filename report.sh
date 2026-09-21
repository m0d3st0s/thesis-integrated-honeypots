#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
for argument in "$@"; do
    case "$argument" in
        --config|--config=*) exec python3 "$PROJECT_DIR/report_config.py" "$@" ;;
    esac
done
exec "$PROJECT_DIR/collect_report.sh" "$@"

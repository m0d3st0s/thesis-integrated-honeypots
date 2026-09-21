#!/usr/bin/env bash
set -euo pipefail
umask 077

PROJECT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
export KUBECONFIG="$HOME/.kube/thesis-k3s.yaml"

TODAY=$(date -u +%F)
YESTERDAY=$(date -u -d "$TODAY 00:00:00 UTC -1 day" +%F)

echo "Reporting UTC day: $YESTERDAY"
exec "$PROJECT_DIR/report.sh" \
    "${YESTERDAY}T00:00:00Z" \
    "${TODAY}T00:00:00Z"

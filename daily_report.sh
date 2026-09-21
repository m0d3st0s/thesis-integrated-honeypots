#!/usr/bin/env bash
set -euo pipefail
umask 077

PROJECT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/thesis-k3s.yaml}"
REPORT_CONFIG="${THESIS_REPORT_CONFIG:-$PROJECT_DIR/config/reporting.json}"

exec python3 - "$PROJECT_DIR" "$REPORT_CONFIG" <<'DAILY_PY'
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

project = Path(sys.argv[1])
config_path = Path(sys.argv[2]).expanduser().resolve()

try:
    config = json.loads(config_path.read_text())
    if config.get("schema_version") != 1:
        raise ValueError("Unsupported reporting configuration.")

    conpot = config["conpot"]
    for key in ("deployment", "namespace", "log", "log_id", "labels"):
        if not isinstance(conpot.get(key), str) or not conpot[key]:
            raise ValueError("Missing or invalid Conpot setting: " + key)

    def resolve_path(value):
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = config_path.parent / path
        return path.resolve()

    labels = resolve_path(conpot["labels"])
    log = resolve_path(conpot["log"])
    if not labels.is_file():
        raise ValueError("Controlled-test label file is missing.")

    root = resolve_path(config["reports_root"])
    root.mkdir(parents=True, exist_ok=True)

    today = datetime.now(timezone.utc).date()
    yesterday = today - timedelta(days=1)
    parent = Path(tempfile.mkdtemp(
        prefix="daily-combined-" + str(yesterday) + "-",
        dir=root,
    ))
    (parent / "reporting-config.json").write_text(
        json.dumps(config, indent=2) + "\n"
    )

    print("Reporting UTC day:", yesterday, flush=True)
    print("Daily evidence directory:", parent, flush=True)

    command = [
        sys.executable,
        str(project / "collect_combined_report.py"),
        str(yesterday) + "T00:00:00Z",
        str(today) + "T00:00:00Z",
        "--output", str(parent / "report"),
        "--conpot-log", str(log),
        "--conpot-deployment", conpot["deployment"],
        "--conpot-namespace", conpot["namespace"],
        "--conpot-log-id", conpot["log_id"],
        "--conpot-labels", str(labels),
    ]
    os.execv(sys.executable, command)
except (OSError, ValueError, KeyError, TypeError) as exc:
    raise SystemExit("Daily report failed: " + str(exc))
DAILY_PY

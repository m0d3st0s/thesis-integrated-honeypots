#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 SINCE UNTIL [--output DIR] [--deployment NAME --namespace NS --database PATH --database-id ID --cowrie-log PATH --labels PATH --history-root PATH --reports-root PATH]" >&2
    exit 1
fi
SINCE="$1"
UNTIL="$2"
shift 2
PROJECT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
# Legacy defaults remain for existing direct callers. Configured reports supply all settings.
RELEASE="auto-mixed-01"
NAMESPACE="honeypots"
DATABASE="/var/lib/thesis-honeypots/auto-mixed-01/dionaea/dionaea.sqlite"
DATABASE_ID="auto-mixed-01-initial"
COWRIE_LOG="/var/log/honeypots/auto-mixed-01/cowrie/cowrie.json"
LABELS="$PROJECT_DIR/controlled-test-events-mixed.txt"
HISTORY_ROOT="$HOME/thesis/runs"
REPORTS_ROOT="$HOME/thesis/reports"
REPORT_DIR=""
while [ "$#" -gt 0 ]; do
    if [ "$#" -lt 2 ] || [ -z "$2" ]; then
        echo "Missing option value: $1" >&2
        exit 1
    fi
    case "$1" in
        --output) REPORT_DIR="$2" ;;
        --deployment) RELEASE="$2" ;;
        --namespace) NAMESPACE="$2" ;;
        --database) DATABASE="$2" ;;
        --database-id) DATABASE_ID="$2" ;;
        --cowrie-log) COWRIE_LOG="$2" ;;
        --labels) LABELS="$2" ;;
        --history-root) HISTORY_ROOT="$2" ;;
        --reports-root) REPORTS_ROOT="$2" ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift 2
done

# Validate the window before collecting anything.
python3 - "$SINCE" "$UNTIL" <<'PY'
import sys
from datetime import datetime

def parse(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise SystemExit("Both timestamps must include a timezone.")
    return result

if parse(sys.argv[1]) >= parse(sys.argv[2]):
    raise SystemExit("SINCE must be earlier than UNTIL.")
PY

test -f "$LABELS"
umask 077

if [ -n "$REPORT_DIR" ]; then
    mkdir -- "$REPORT_DIR"
else
    mkdir -p "$REPORTS_ROOT"
    REPORT_DIR=$(mktemp -d "$REPORTS_ROOT/report-XXXXXXXX")
fi
echo "Report directory: $REPORT_DIR"
trap 'echo "Collection failed. Inspect: $REPORT_DIR" >&2' ERR

date -u +%Y-%m-%dT%H:%M:%SZ > "$REPORT_DIR/collection-started.txt"

echo "1. Recording deployment metadata..."
kubectl get service "$RELEASE" -n "$NAMESPACE" -o json \
    > "$REPORT_DIR/service.json"

kubectl get pods -n "$NAMESPACE" \
    -l "app.kubernetes.io/instance=$RELEASE" -o json \
    > "$REPORT_DIR/pods.json"

echo "2. Collecting current logs and a database snapshot..."
python3 - "$COWRIE_LOG" "$DATABASE" "$REPORT_DIR" "$DATABASE_ID" "$RELEASE" "$NAMESPACE" <<'PY'
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

log_path = Path(sys.argv[1])
database = Path(sys.argv[2])
folder = Path(sys.argv[3])

def now():
    return datetime.now(timezone.utc).isoformat()


metadata = {
    "schema_version": 1,
    "cowrie_source": str(log_path),
    "dionaea_source": str(database),
    "database_id": sys.argv[4],
    "deployment": sys.argv[5],
    "namespace": sys.argv[6],
    "limitations": [
        "Collects the configured current log and uncompressed YYYY-MM-DD rotations; deleted, compressed, or differently named logs are not included.",
        "The two sources are collected sequentially, not atomically.",
        "Collection times do not establish continuous monitoring coverage.",
    ],
}

metadata["cowrie_read_started"] = now()

import hashlib
import re
import stat

folder_path = log_path.parent
current_name = log_path.name
rotated_pattern = re.compile(re.escape(current_name) + r"\.\d{4}-\d{2}-\d{2}")

def inventory():
    result = {}
    for path in folder_path.iterdir():
        if path.name != current_name and not rotated_pattern.fullmatch(path.name):
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit("Expected a regular log file: " + str(path))
        result[path.name] = (info.st_dev, info.st_ino, info.st_size)
    if current_name not in result:
        raise SystemExit("Current Cowrie log is missing.")
    return result

before = inventory()
names = sorted(name for name in before if name != current_name)
names.append(current_name)

chunks = []
files = []
omitted_total = 0

for name in names:
    path = folder_path / name
    expected = before[name]
    with path.open("rb") as source:
        info = os.fstat(source.fileno())
        if (info.st_dev, info.st_ino) != expected[:2]:
            raise SystemExit("Cowrie logs changed during collection; rerun.")
        raw = source.read(expected[2])

    if len(raw) != expected[2]:
        raise SystemExit("Cowrie log was truncated during collection; rerun.")

    end = raw.rfind(b"\n") + 1
    complete = raw[:end]
    omitted = len(raw) - end

    if omitted and name != current_name:
        raise SystemExit("Incomplete final line in rotated log: " + name)

    records = 0
    for number, line in enumerate(complete.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError as exc:
            raise SystemExit(
                "Invalid JSON in {} line {}: {}".format(name, number, exc)
            )
        if not isinstance(event, dict):
            raise SystemExit("Expected a JSON object in " + name)
        records += 1

    chunks.append(complete)
    omitted_total += omitted
    files.append({
        "name": name,
        "bytes_read": len(raw),
        "bytes_included": len(complete),
        "trailing_bytes_omitted": omitted,
        "json_records": records,
        "included_sha256": hashlib.sha256(complete).hexdigest(),
    })

after = inventory()
if set(before) != set(after):
    raise SystemExit("Cowrie logs rotated during collection; rerun.")

for name in names:
    if before[name][:2] != after[name][:2]:
        raise SystemExit("Cowrie log identity changed; rerun.")
    if after[name][2] < before[name][2]:
        raise SystemExit("Cowrie log was truncated; rerun.")
    if name != current_name and after[name][2] != before[name][2]:
        raise SystemExit("A rotated Cowrie log changed; rerun.")

snapshot = folder / "cowrie-snapshot.jsonl"
snapshot.write_bytes(b"".join(chunks))

metadata["cowrie_files"] = files
metadata["cowrie_trailing_bytes_omitted"] = omitted_total
metadata["cowrie_read_finished"] = now()

metadata["dionaea_backup_started"] = now()
destination = folder / "dionaea.sqlite"
source = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
backup = sqlite3.connect(destination)
try:
    source.backup(backup)
    if backup.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise SystemExit("Dionaea snapshot integrity check failed.")
    metadata["dionaea_connection_rows"] = backup.execute(
        "SELECT COUNT(*) FROM connections"
    ).fetchone()[0]
finally:
    backup.close()
    source.close()

metadata["dionaea_backup_finished"] = now()

path = folder / "collection.json"
path.write_text(json.dumps(metadata, indent=2) + "\n")
print("Snapshots collected; Dionaea integrity verified.")
PY

echo "3. Normalizing and classifying connections..."
python3 "$PROJECT_DIR/export_dionaea.py" \
    "$REPORT_DIR/dionaea.sqlite" \
    --database-id "$DATABASE_ID" \
    --deployment "$RELEASE" \
    > "$REPORT_DIR/dionaea-normalized.jsonl"

# Preserve the labels used for this particular report.
cp "$LABELS" \
    "$REPORT_DIR/controlled-test-events.txt"

TEST_ARGS=()
while IFS= read -r event_id || [ -n "$event_id" ]; do
    if [ -n "$event_id" ]; then
        TEST_ARGS+=(--test-event "$event_id")
    fi
done < "$REPORT_DIR/controlled-test-events.txt"

python3 "$PROJECT_DIR/compare_connections.py" \
    --cowrie "$REPORT_DIR/cowrie-snapshot.jsonl" \
    --dionaea "$REPORT_DIR/dionaea-normalized.jsonl" \
    --deployment "$RELEASE" \
    "${TEST_ARGS[@]}" \
    > "$REPORT_DIR/all-connections.json"

echo "4. Applying the reporting window..."
python3 "$PROJECT_DIR/window_feed.py" \
    "$REPORT_DIR/all-connections.json" \
    --since "$SINCE" --until "$UNTIL" \
    > "$REPORT_DIR/window-feed.json"

python3 - "$REPORT_DIR" <<'PY'
import json
import sys
from pathlib import Path

folder = Path(sys.argv[1])
report = json.loads((folder / "window-feed.json").read_text())
service = json.loads((folder / "service.json").read_text())
ports = {p["name"]: p for p in service["spec"]["ports"]}

lines = [
    "HONEYPOT INTERACTION REPORT",
    "Deployment: " + report["deployment"],
    "Since (inclusive): " + report["window"]["since_inclusive"],
    "Until (exclusive): " + report["window"]["until_exclusive"],
    "Coverage: supplied snapshots; full-window coverage is not established.",
    "Metric: incoming connection starts, not confirmed attacks.",
    "",
    "Total connections: " + str(report["total_incoming_connections"]),
]

for group in report["by_service"]:
    mapping = ports.get(group["service"], {})
    lines.append(
        "{service}: {count} connections; {tests} controlled tests; "
        "{other} unclassified; service port {port}; NodePort {node}".format(
            service=group["service"].upper(),
            count=group["incoming_connections"],
            tests=group["controlled_test_connections"],
            other=group["unclassified_connections"],
            port=mapping.get("port", "unknown"),
            node=mapping.get("nodePort", "unknown"),
        )
    )

lines.extend([
    "",
    "Port mappings describe the Service at collection time.",
    "Controlled tests do not establish attacker preferences.",
    "Unclassified connections require review.",
    "Collection details: collection.json",
])

text = "\n".join(lines) + "\n"
(folder / "report.txt").write_text(text)
print(text)
PY

python3 "$PROJECT_DIR/attach_service_history.py" \
    "$REPORT_DIR" \
    --history-root "$HISTORY_ROOT" \
    --namespace "$NAMESPACE"

date -u +%Y-%m-%dT%H:%M:%SZ > "$REPORT_DIR/report-completed.txt"
echo "Report completed: $REPORT_DIR"

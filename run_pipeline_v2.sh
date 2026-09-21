#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$HOME/thesis/integrated-system"
TARGET_IP="192.168.77.20"
RELEASE="auto-mixed-01"
NAMESPACE="honeypots"
DATABASE="/var/lib/thesis-honeypots/$RELEASE/dionaea/dionaea.sqlite"
DATABASE_ID="auto-mixed-01-initial"

for command in python3 nmap curl unzip helm kubectl flock; do
    command -v "$command" >/dev/null || {
        echo "Missing command: $command" >&2
        exit 1
    }
done

# Prevent two copies of this pipeline from running together.
exec 9>"$PROJECT_DIR/.mixed-pipeline.lock"
flock -n 9 || {
    echo "Another mixed pipeline run is active." >&2
    exit 1
}

mkdir -p "$HOME/thesis/runs"
RUN_DIR=$(mktemp -d "$HOME/thesis/runs/mixed-XXXXXXXX")
echo "Run directory: $RUN_DIR"
trap 'echo "Pipeline stopped. Inspect results in: $RUN_DIR" >&2' ERR

curl --fail --silent --show-error --max-time 10 \
    http://127.0.0.1:8081/ >/dev/null

kubectl get namespace "$NAMESPACE" >/dev/null
kubectl get networkpolicy deny-outbound -n "$NAMESPACE" >/dev/null
helm status "$RELEASE" -n "$NAMESPACE" >/dev/null
sudo -v

# Require the previously migrated database; never initialize over it.
sudo python3 - "$DATABASE" <<'PY'
import sqlite3
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_file():
    raise SystemExit("Persistent database missing; stopping.")

db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
try:
    if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
        raise SystemExit("Persistent database integrity check failed.")
    print("Existing Dionaea connections:",
          db.execute("SELECT COUNT(*) FROM connections").fetchone()[0])
finally:
    db.close()
PY

echo "1. Discovering the lab target..."
sudo nmap -sn -n -e enp0s8 "$TARGET_IP" \
    -oX - > "$RUN_DIR/discovery.xml"

python3 - "$RUN_DIR/discovery.xml" "$TARGET_IP" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
found = any(
    host.find("status") is not None
    and host.find("status").get("state") == "up"
    and any(a.get("addr") == sys.argv[2]
            for a in host.findall("address"))
    for host in root.findall("host")
)
if not found:
    raise SystemExit("Target was not discovered; stopping.")
PY

echo "2. Identifying services..."
nmap -sT -sV --version-light -n \
    -p 22,80,443,445 "$TARGET_IP" \
    -oX "$RUN_DIR/services.xml"

echo "3. Building the profile and request..."
python3 "$PROJECT_DIR/profiler_v2.py" "$RUN_DIR/services.xml" \
    > "$RUN_DIR/profile.json"

python3 "$PROJECT_DIR/build_request_v2.py" "$RUN_DIR/profile.json" \
    > "$RUN_DIR/request.json"

python3 - "$RUN_DIR/request.json" <<'PY'
import json
import sys

request = json.load(open(sys.argv[1]))
hp = request["honeypots"]
if request["name"] != "auto-mixed-01":
    raise SystemExit("Unexpected release name.")
if set(hp["names"]) != {"cowrie", "dionaea"}:
    raise SystemExit("This pipeline requires both SSH and HTTP; stopping.")
if hp["cowrie"]["services"] != [{"ssh": 22}]:
    raise SystemExit("Unexpected SSH mapping.")
if hp["dionaea"]["services"] != [{"http": 80}]:
    raise SystemExit("Unexpected HTTP mapping.")
PY

echo "4. Generating and preparing the chart..."
curl --fail --silent --show-error \
    --connect-timeout 5 --max-time 120 \
    -H 'Content-Type: application/json' \
    --data-binary @"$RUN_DIR/request.json" \
    http://127.0.0.1:8081/custom_build_endpoint \
    --output "$RUN_DIR/chart.zip"

unzip -tq "$RUN_DIR/chart.zip"
unzip -q "$RUN_DIR/chart.zip" -d "$RUN_DIR"

CHART_DIR="$RUN_DIR/$RELEASE"
python3 "$PROJECT_DIR/prepare_mixed_chart.py" "$CHART_DIR"

HELM_VALUES=(
    --set serviceAccount.automount=false
    --set replicaCount=1
    --set autoscaling.enabled=false
)

echo "5. Validating the chart..."
helm lint "$CHART_DIR" "${HELM_VALUES[@]}"

helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" "${HELM_VALUES[@]}" \
    > "$RUN_DIR/rendered.yaml"

kubectl apply --dry-run=server -n "$NAMESPACE" \
    -f "$RUN_DIR/rendered.yaml"

echo "6. Deploying..."
sudo install -d -m 750 -o 1000 -g 1000 \
    "/var/log/honeypots/$RELEASE/cowrie"
sudo install -d -m 755 -o 0 -g 0 \
    "/var/log/honeypots/$RELEASE/dionaea"

helm upgrade "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" "${HELM_VALUES[@]}" \
    --wait --timeout 5m

kubectl exec -n "$NAMESPACE" "deployment/$RELEASE" \
    -c cowrie -- \
    sh -c 'test -w /cowrie/cowrie-git/var/log/cowrie/cowrie.json'

kubectl get service "$RELEASE" -n "$NAMESPACE" -o json \
    > "$RUN_DIR/service.json"
kubectl get pods -n "$NAMESPACE" \
    -l "app.kubernetes.io/instance=$RELEASE" -o json \
    > "$RUN_DIR/pods.json"

echo "7. Collecting log and database snapshots..."
sudo cat "/var/log/honeypots/$RELEASE/cowrie/cowrie.json" \
    > "$RUN_DIR/cowrie-snapshot.jsonl"

sudo python3 - "$DATABASE" "$RUN_DIR/dionaea.sqlite" <<'PY'
import os
import sqlite3
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
destination = Path(sys.argv[2])
if destination.exists():
    raise SystemExit("Snapshot destination already exists.")

source = sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True)
backup = sqlite3.connect(destination)
try:
    source.backup(backup)
    if backup.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise SystemExit("Snapshot integrity check failed.")
finally:
    backup.close()
    source.close()

os.chown(destination, int(os.environ["SUDO_UID"]),
         int(os.environ["SUDO_GID"]))
print("Dionaea snapshot verified.")
PY

python3 "$PROJECT_DIR/export_dionaea.py" \
    "$RUN_DIR/dionaea.sqlite" \
    --database-id "$DATABASE_ID" \
    --deployment "$RELEASE" \
    > "$RUN_DIR/dionaea-normalized.jsonl"

echo "8. Building the combined feed..."
TEST_ARGS=()
while IFS= read -r event_id || [ -n "$event_id" ]; do
    if [ -n "$event_id" ]; then
        TEST_ARGS+=(--test-event "$event_id")
    fi
done < "$PROJECT_DIR/controlled-test-events-mixed.txt"

python3 "$PROJECT_DIR/compare_connections.py" \
    --cowrie "$RUN_DIR/cowrie-snapshot.jsonl" \
    --dionaea "$RUN_DIR/dionaea-normalized.jsonl" \
    --deployment "$RELEASE" \
    "${TEST_ARGS[@]}" \
    > "$RUN_DIR/feed.json"

python3 - "$RUN_DIR/feed.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
print(json.dumps({
    "total_incoming_connections": report["total_incoming_connections"],
    "duplicate_records_removed": report["duplicate_records_removed"],
    "by_service": report["by_service"],
}, indent=2))
PY

echo "Pipeline completed. Results: $RUN_DIR"
kubectl get service "$RELEASE" -n "$NAMESPACE"

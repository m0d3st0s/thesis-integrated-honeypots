#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$HOME/thesis/integrated-system"
RELEASE="auto-mixed-01"
NAMESPACE="honeypots"
DATABASE="/var/lib/thesis-honeypots/$RELEASE/dionaea/dionaea.sqlite"

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
cp "$PROJECT_DIR/image-pins.yaml" "$RUN_DIR/image-pins.yaml"
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

echo "1–3. Discovering, profiling, and planning..."
"$PROJECT_DIR/profile_lab.sh" "$RUN_DIR/lab-profile"

python3 - "$RUN_DIR/lab-profile" <<'CHECK'
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

folder = Path(sys.argv[1])
status_path = folder / "profiling-status.json"
if not status_path.exists():
    raise SystemExit("No completed device profiles; deployment stopped.")

status = json.loads(status_path.read_text())
if status["discovered_but_not_profiled"]:
    raise SystemExit(
        "Some discovered devices were not profiled; deployment stopped."
    )
if status["profiled_device_count"] == 0:
    raise SystemExit("No profiled devices; deployment stopped.")

root = ET.parse(folder / "services.xml").getroot()
finished = root.find("./runstats/finished")
if finished is None or finished.get("exit") != "success":
    raise SystemExit("Service scan did not finish successfully.")

print("Devices profiled:", status["profiled_device_count"])
CHECK

cp "$RUN_DIR/lab-profile/profile.json" "$RUN_DIR/profile.json"

python3 "$PROJECT_DIR/build_plan.py" "$RUN_DIR/profile.json" \
    > "$RUN_DIR/deployment-plan.json"

python3 "$PROJECT_DIR/build_request_adaptive.py" \
    "$RUN_DIR/deployment-plan.json" \
    > "$RUN_DIR/request.json"

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
python3 "$PROJECT_DIR/prepare_stateful_chart.py" "$CHART_DIR"

HELM_VALUES=(
    --values "$RUN_DIR/image-pins.yaml"
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

echo "6. Preparing selected honeypots and deploying..."

SELECTED_HONEYPOTS=$(python3 - "$RUN_DIR/request.json" <<'SELECT'
import json
import sys

request = json.load(open(sys.argv[1]))
names = request["honeypots"]["names"]
if not names or not set(names).issubset({"cowrie", "dionaea"}):
    raise SystemExit("Unexpected honeypot selection.")
print(" ".join(sorted(names)))
SELECT
)

has_honeypot() {
    case " $SELECTED_HONEYPOTS " in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
    esac
}

echo "Selected honeypots: $SELECTED_HONEYPOTS"

# Preserve the previous port mapping before changing the Service.
kubectl get service "$RELEASE" -n "$NAMESPACE" -o json \
    > "$RUN_DIR/service-before.json"

kubectl get pods -n "$NAMESPACE" \
    -l "app.kubernetes.io/instance=$RELEASE" -o json \
    > "$RUN_DIR/pods-before.json"
if has_honeypot cowrie; then
    COWRIE_STATE="/var/lib/thesis-honeypots/$RELEASE/cowrie"
    sudo test -d "$COWRIE_STATE"
    for key in rsa ecdsa ed25519; do
        sudo test -s "$COWRIE_STATE/ssh_host_${key}_key"
        sudo test -s "$COWRIE_STATE/ssh_host_${key}_key.pub"
    done
    sudo install -d -m 750 -o 1000 -g 1000 \
        "/var/log/honeypots/$RELEASE/cowrie"
fi

if has_honeypot dionaea; then
    sudo install -d -m 755 -o 0 -g 0 \
        "/var/log/honeypots/$RELEASE/dionaea"
fi

python3 "$PROJECT_DIR/record_service_state.py" \
    "$RUN_DIR/service-state-before.json" \
    --phase before_upgrade

helm upgrade "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" "${HELM_VALUES[@]}" \
    --wait --timeout 5m

if has_honeypot cowrie; then
    kubectl exec -n "$NAMESPACE" "deployment/$RELEASE" \
        -c cowrie -- \
        sh -c 'test -w /cowrie/cowrie-git/var/log/cowrie/cowrie.json'
fi

if has_honeypot dionaea; then
    kubectl exec -n "$NAMESPACE" "deployment/$RELEASE" \
        -c dionaea -- python3 -c '
import sqlite3
db = sqlite3.connect(
    "file:/opt/dionaea/var/lib/dionaea/dionaea.sqlite?mode=ro",
    uri=True,
)
try:
    if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
        raise SystemExit("Dionaea database integrity check failed.")
    print("Dionaea database is accessible and healthy.")
finally:
    db.close()
'
fi

kubectl get service "$RELEASE" -n "$NAMESPACE" -o json \
    > "$RUN_DIR/service.json"

python3 "$PROJECT_DIR/record_service_state.py" \
    "$RUN_DIR/service-state-after.json" \
    --phase after_upgrade
kubectl get pods -n "$NAMESPACE" \
    -l "app.kubernetes.io/instance=$RELEASE" -o json \
    > "$RUN_DIR/pods.json"

echo "Deployment pipeline completed. Results: $RUN_DIR"
kubectl get service "$RELEASE" -n "$NAMESPACE"
echo "Generate a report separately with collect_report.sh SINCE UNTIL."

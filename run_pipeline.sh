#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$HOME/thesis/integrated-system"
TARGET_IP="192.168.77.20"
RELEASE="auto-ssh-01"
NAMESPACE="honeypots"

mkdir -p "$HOME/thesis/runs"
RUN_DIR=$(mktemp -d "$HOME/thesis/runs/run-XXXXXXXX")
echo "Run directory: $RUN_DIR"

# Check prerequisites before starting.
for command in python3 nmap curl unzip helm kubectl; do
    command -v "$command" >/dev/null || {
        echo "Missing command: $command" >&2
        exit 1
    }
done

curl --fail --silent --show-error --max-time 10 \
    http://127.0.0.1:8081/ >/dev/null
kubectl get namespace "$NAMESPACE" >/dev/null
kubectl get networkpolicy deny-outbound -n "$NAMESPACE" >/dev/null
sudo -v

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
    and any(
        address.get("addr") == sys.argv[2]
        for address in host.findall("address")
    )
    for host in root.findall("host")
)
if not found:
    raise SystemExit("Target was not discovered; stopping.")
PY

echo "2. Identifying services..."
nmap -sT -sV --version-light -n \
    -p 22,80,443,445 "$TARGET_IP" \
    -oX "$RUN_DIR/services.xml"

echo "3. Building the profile and HoneyChart request..."
python3 "$PROJECT_DIR/profiler.py" "$RUN_DIR/services.xml" \
    > "$RUN_DIR/profile.json"

python3 "$PROJECT_DIR/build_request.py" "$RUN_DIR/profile.json" \
    > "$RUN_DIR/request.json"

echo "4. Generating the chart..."
curl --fail --silent --show-error \
    --connect-timeout 5 --max-time 120 \
    -H 'Content-Type: application/json' \
    --data-binary @"$RUN_DIR/request.json" \
    http://127.0.0.1:8081/custom_build_endpoint \
    --output "$RUN_DIR/chart.zip"

unzip -tq "$RUN_DIR/chart.zip"
unzip -q "$RUN_DIR/chart.zip" -d "$RUN_DIR"

CHART_DIR="$RUN_DIR/$RELEASE"

# Preserve the unsuitable generated HTTP test outside the chart.
if [ -f "$CHART_DIR/templates/tests/test-connection.yaml" ]; then
    mv "$CHART_DIR/templates/tests/test-connection.yaml" \
       "$RUN_DIR/unused-http-test.yaml"
fi

echo "5. Validating the chart..."
helm lint "$CHART_DIR" --set serviceAccount.automount=false

helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" \
    --set serviceAccount.automount=false \
    > "$RUN_DIR/rendered.yaml"

kubectl apply --dry-run=server -n "$NAMESPACE" \
    -f "$RUN_DIR/rendered.yaml"

echo "6. Preparing logs and deploying..."
# UID/GID verified for the Cowrie image in this lab.
sudo install -d -m 750 -o 1000 -g 1000 \
    "/var/log/honeypots/$RELEASE"

helm upgrade --install "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" \
    --set serviceAccount.automount=false \
    --wait --timeout 5m

kubectl exec -n "$NAMESPACE" "deployment/$RELEASE" -- \
    sh -c 'test -w /cowrie/cowrie-git/var/log/cowrie/cowrie.json'

kubectl get service "$RELEASE" -n "$NAMESPACE" -o json \
    > "$RUN_DIR/service.json"

kubectl get pods -n "$NAMESPACE" \
    -l "app.kubernetes.io/instance=$RELEASE" -o json \
    > "$RUN_DIR/pods.json"


echo "7. Building the interaction summary..."
sudo cat "/var/log/honeypots/$RELEASE/cowrie.json" \
    > "$RUN_DIR/cowrie-snapshot.jsonl"

TEST_ARGS=()
if [ -f "$PROJECT_DIR/controlled-test-sessions.txt" ]; then
    while IFS= read -r session_id || [ -n "$session_id" ]; do
        if [ -n "$session_id" ]; then
            TEST_ARGS+=(--test-session "$session_id")
        fi
    done < "$PROJECT_DIR/controlled-test-sessions.txt"
fi

python3 "$PROJECT_DIR/build_feed.py" \
    "$RUN_DIR/cowrie-snapshot.jsonl" \
    --service "$RUN_DIR/service.json" \
    "${TEST_ARGS[@]}" \
    > "$RUN_DIR/feed.json"

cat "$RUN_DIR/feed.json"

echo "Pipeline completed. Results: $RUN_DIR"
kubectl get service "$RELEASE" -n "$NAMESPACE"

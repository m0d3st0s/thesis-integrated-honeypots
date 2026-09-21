import json
import subprocess
import uuid
from pathlib import Path


def inspect_retained_dionaea(
    namespace, node_hostname, state_directory, log_directory, evidence_directory
):
    evidence_directory = Path(evidence_directory)
    evidence_directory.mkdir(parents=True, exist_ok=False)

    project = Path(__file__).resolve().parent
    recipe = json.loads(
        (project / "assets/conpot-modbus/manifest.json").read_text()
    )
    image = recipe["image"]
    if not image.startswith("ghcr.io/parasecurity/conpot@sha256:"):
        raise ValueError("Expected the pinned inspection image.")

    name = "state-check-" + uuid.uuid4().hex[:10]
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"app.kubernetes.io/name": "thesis-state-inspector"},
        },
        "spec": {
            "restartPolicy": "Never",
            "activeDeadlineSeconds": 180,
            "automountServiceAccountToken": False,
            "nodeSelector": {"kubernetes.io/hostname": node_hostname},
            "containers": [{
                "name": "inspector",
                "image": image,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python3", "-c", "import time; time.sleep(150)"],
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 1000,
                    "runAsGroup": 1000,
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                },
                "volumeMounts": [
                    {
                        "name": "state",
                        "mountPath": "/retained-state",
                        "readOnly": True,
                    },
                    {
                        "name": "logs",
                        "mountPath": "/retained-logs",
                        "readOnly": True,
                    },
                ],
            }],
            "volumes": [
                {
                    "name": "state",
                    "hostPath": {
                        "path": str(state_directory),
                        "type": "Directory",
                    },
                },
                {
                    "name": "logs",
                    "hostPath": {
                        "path": str(log_directory),
                        "type": "Directory",
                    },
                },
            ],
        },
    }

    code = """
import json
import sqlite3
from pathlib import Path

if not Path('/retained-logs').is_dir():
    raise SystemExit('Retained log directory is missing.')
db = sqlite3.connect(
    'file:/retained-state/dionaea.sqlite?mode=ro', uri=True)
try:
    if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
        raise SystemExit('Database integrity check failed.')
    count = db.execute('SELECT COUNT(*) FROM connections').fetchone()[0]
    print(json.dumps({
        'database_integrity': 'ok',
        'connection_rows': count,
        'inspection_method': 'read_only_retained_storage',
        'log_directory_present': True
    }))
finally:
    db.close()
"""

    manifest = evidence_directory / "inspection-pod.json"
    manifest.write_text(json.dumps(pod, indent=2) + "\n")
    created = False
    try:
        subprocess.run(
            ["kubectl", "create", "-f", str(manifest)],
            check=True, timeout=60,
        )
        created = True
        subprocess.run([
            "kubectl", "wait", "-n", namespace,
            "--for=condition=Ready", "pod/" + name, "--timeout=90s",
        ], check=True, timeout=100)

        result = subprocess.run([
            "kubectl", "exec", "-n", namespace, name,
            "-c", "inspector", "--", "python3", "-c", code,
        ], capture_output=True, text=True, timeout=60)
        (evidence_directory / "stdout.txt").write_text(result.stdout)
        (evidence_directory / "stderr.txt").write_text(result.stderr)
        result.check_returncode()
        summary = json.loads(result.stdout)
        (evidence_directory / "result.json").write_text(
            json.dumps(summary, indent=2) + "\n"
        )
        return summary
    finally:
        if created:
            cleanup = subprocess.run([
                "kubectl", "delete", "pod", name, "-n", namespace,
                "--ignore-not-found", "--wait=false",
            ], capture_output=True, text=True, timeout=60)
            (evidence_directory / "cleanup.txt").write_text(
                cleanup.stdout + cleanup.stderr
            )
            if cleanup.returncode:
                raise RuntimeError("Failed to delete inspection Pod: " + name)

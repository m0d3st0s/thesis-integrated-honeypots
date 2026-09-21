import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("output", type=Path)
parser.add_argument(
    "--phase",
    required=True,
    choices=["baseline", "before_upgrade", "after_upgrade"],
)
args = parser.parse_args()

def now():
    return datetime.now(timezone.utc).isoformat()

try:
    if args.output.exists():
        raise ValueError("Output already exists; refusing to overwrite.")

    started = now()
    result = subprocess.run(
        [
            "kubectl", "get", "service", "auto-mixed-01",
            "-n", "honeypots", "-o", "json",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    finished = now()
    service = json.loads(result.stdout)

    metadata = service["metadata"]
    spec = service["spec"]

    record = {
        "schema_version": 1,
        "phase": args.phase,
        "observation_started_at": started,
        "observation_finished_at": finished,
        "deployment": "auto-mixed-01",
        "namespace": "honeypots",
        "service_uid": metadata["uid"],
        "resource_version": metadata["resourceVersion"],
        "service_type": spec["type"],
        "cluster_ip": spec.get("clusterIP"),
        "ports": [
            {
                "name": port.get("name"),
                "transport": port.get("protocol", "TCP"),
                "service_port": port["port"],
                "target_port": port.get("targetPort", port["port"]),
                "node_port": port.get("nodePort"),
            }
            for port in spec["ports"]
        ],
        "interpretation": (
            "Service configuration observed during the recorded read interval. "
            "Not an exact activation time, availability measurement, "
            "or proof of an individual connection's external destination port."
        ),
        "raw_service": service,
    }

    with args.output.open("x") as output:
        json.dump(record, output, indent=2)
        output.write("\n")

except (
    OSError, ValueError, KeyError, TypeError,
    subprocess.SubprocessError,
) as exc:
    parser.exit(1, "Error: {}\n".format(exc))

print("Saved Service observation:", args.output)

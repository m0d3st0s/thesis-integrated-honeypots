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
    choices=("baseline", "before_upgrade", "after_upgrade"),
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
    )
    finished = now()
    service = json.loads(result.stdout)

    record = {
        "schema_version": 1,
        "phase": args.phase,
        "observation_started_at": started,
        "observation_finished_at": finished,
        "release": "auto-mixed-01",
        "namespace": "honeypots",
        "service_name": service["metadata"]["name"],
        "service_uid": service["metadata"]["uid"],
        "resource_version": service["metadata"]["resourceVersion"],
        "service_type": service["spec"]["type"],
        "cluster_ip": service["spec"].get("clusterIP"),
        "ports": [
            {
                "name": port.get("name"),
                "transport": port.get("protocol", "TCP"),
                "service_port": port["port"],
                "target_port": port.get("targetPort", port["port"]),
                "node_port": port.get("nodePort"),
            }
            for port in service["spec"]["ports"]
        ],
        "limitations": [
            "Observation time is not the configuration's exact effective time.",
            "Service configuration does not establish application availability.",
            "This observation does not prove an event used a particular NodePort.",
        ],
        "raw_service": service,
    }

    with args.output.open("x") as output:
        json.dump(record, output, indent=2)
        output.write("\n")

except subprocess.CalledProcessError as exc:
    parser.exit(1, "kubectl failed: " + exc.stderr)
except (OSError, ValueError, KeyError, TypeError) as exc:
    parser.exit(1, "Error: {}\n".format(exc))

print("Recorded service state:", args.output)

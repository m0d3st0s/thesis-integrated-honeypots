import argparse
import json
from pathlib import Path

EXPECTED = {
    ("cowrie", "ssh", "tcp", 22): 2222,
    ("dionaea", "http", "tcp", 80): 80,
}

parser = argparse.ArgumentParser()
parser.add_argument("plan", type=Path)
args = parser.parse_args()

try:
    plan = json.loads(args.plan.read_text())

    if plan.get("schema_version") != 1:
        raise ValueError("Expected plan schema version 1.")
    if plan.get("policy") != "shared-service-honeypots-v1":
        raise ValueError("Unsupported selection policy.")
    allowed_statuses = {
        "compatible_with_current_mixed_layout",
        "deployment_layout_change_required",
    }
    if plan.get("status") not in allowed_statuses:
        raise ValueError("Plan does not permit a supported deployment.")
    if plan.get("review_items"):
        raise ValueError("Plan contains unresolved review items.")
    if plan.get("candidate_release") != "auto-mixed-01":
        raise ValueError("Unexpected release name.")

    services = plan["services"]
    if plan.get("planned_service_count") != len(services):
        raise ValueError("Planned service count does not match the service list.")

    mappings = {}
    for item in services:
        port = item["service_port"]
        container_port = item["container_port"]
        if type(port) is not int or type(container_port) is not int:
            raise ValueError("Ports must be integers.")

        key = (
            item["honeypot"],
            item["service"],
            item["transport"],
            port,
        )
        if key not in EXPECTED or container_port != EXPECTED[key]:
            raise ValueError("Unsupported service mapping: " + str(key))
        if key in mappings:
            raise ValueError("Duplicate service mapping.")

        sources = item["source_devices"]
        if (
            not isinstance(sources, list)
            or not sources
            or any(not isinstance(ip, str) for ip in sources)
            or len(set(sources)) != len(sources)
            or item["source_device_count"] != len(sources)
        ):
            raise ValueError("Invalid source-device list.")

        mappings[key] = item

    if not mappings:
        raise ValueError("No supported services; existing deployment must remain unchanged.")
    if not set(mappings).issubset(EXPECTED):
        raise ValueError("Unsupported deployment mapping.")

    name = "auto-mixed-01"
    honeypots = {"names": []}

    for key in sorted(mappings):
        hp, service, transport, port = key
        honeypots["names"].append(hp)
        honeypots[hp] = {
            "volumes": [f"/var/log/honeypots/{name}/{hp}"],
            "services": [{service: port}],
            "containerports": [EXPECTED[key]],
            "protocols": [transport.upper()],
        }

    payload = {
        "name": name,
        "service": {"type": "NodePort", "lbIp": None},
        "replicaCount": 1,
        "honeypots": honeypots,
    }

except (OSError, ValueError, KeyError, TypeError) as exc:
    parser.exit(1, "Error: {}\n".format(exc))

print(json.dumps(payload, indent=2))

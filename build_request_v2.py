import argparse
import json
from pathlib import Path

CATALOG = {
    ("cowrie", "ssh", "tcp"): 2222,
    ("dionaea", "http", "tcp"): 80,
}

parser = argparse.ArgumentParser()
parser.add_argument("profile", type=Path)
args = parser.parse_args()

try:
    profile = json.loads(args.profile.read_text())
    if profile.get("schema_version") != 2:
        raise ValueError("Expected profile schema version 2.")

    devices = profile["devices"]
    if len(devices) != 1:
        raise ValueError("This prototype requires exactly one device.")

    device = devices[0]
    if device.get("unsupported_open_services"):
        raise ValueError("Unmapped open services require review.")

    recommendations = device["recommendations"]
    if not recommendations:
        raise ValueError("No honeypot recommendations.")

    name = "auto-mixed-01"
    honeypots = {"names": []}
    used_ports = set()
    used_services = set()

    for recommendation in recommendations:
        hp = recommendation["honeypot"]
        service = recommendation["service"]
        transport = recommendation["transport"]
        key = (hp, service, transport)

        if key not in CATALOG:
            raise ValueError(f"Unsupported mapping: {key}")
        if key in used_services:
            raise ValueError("Repeated service mapping is not supported yet.")

        port = recommendation["observed_port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid service port.")
        if (transport, port) in used_ports:
            raise ValueError("Conflicting exposed ports.")

        used_services.add(key)
        used_ports.add((transport, port))

        if hp not in honeypots:
            honeypots["names"].append(hp)
            honeypots[hp] = {
                "volumes": [f"/var/log/honeypots/{name}/{hp}"],
                "services": [],
                "containerports": [],
                "protocols": [],
            }

        honeypots[hp]["services"].append({service: port})
        honeypots[hp]["containerports"].append(CATALOG[key])
        honeypots[hp]["protocols"].append(transport.upper())

    payload = {
        "name": name,
        "service": {"type": "NodePort", "lbIp": None},
        "replicaCount": 1,
        "honeypots": honeypots,
    }

except (OSError, ValueError, KeyError, TypeError) as exc:
    parser.exit(1, f"Error: {exc}\n")

print(json.dumps(payload, indent=2))

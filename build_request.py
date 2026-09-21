import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("profile", type=Path)
args = parser.parse_args()

try:
    profile = json.loads(args.profile.read_text())
    if profile.get("schema_version") != 1:
        raise ValueError("Unsupported profile schema.")

    candidates = [
        (device, recommendation)
        for device in profile["devices"]
        for recommendation in device.get("recommendations", [])
        if recommendation.get("honeypot") == "cowrie"
        and recommendation.get("service") == "ssh"
    ]

    if len(candidates) != 1:
        raise ValueError("This first adapter requires exactly one SSH recommendation.")

    device, recommendation = candidates[0]
    port = recommendation["observed_port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid observed SSH port.")

    payload = {
        "name": "auto-ssh-01",
        "service": {"type": "NodePort", "lbIp": None},
        "replicaCount": 1,
        "honeypots": {
            "names": ["cowrie"],
            "cowrie": {
                "volumes": ["/var/log/honeypots/auto-ssh-01"],
                "services": [{"ssh": port}],
                "containerports": [2222],
                "protocols": ["TCP"],
            },
        },
    }
except (OSError, ValueError, KeyError, TypeError) as exc:
    parser.exit(1, f"Error: {exc}\n")

print(json.dumps(payload, indent=2))

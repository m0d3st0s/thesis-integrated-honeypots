import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from build_plan_v2 import build_plan


def make_requests(plan):
    if plan["status"] != "planned" or plan["review_items"]:
        raise ValueError("The plan does not permit request generation.")
    if not plan["releases"]:
        raise ValueError("The plan contains no releases.")

    requests = []
    for release in plan["releases"]:
        name = release["name"]
        # The inspected HoneyChart generator requires 3–20 characters.
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,18}[a-z0-9]", name):
            raise ValueError("Release name is incompatible with HoneyChart: " + name)

        honeypots = {"names": []}
        for service in release["services"]:
            hp = service["honeypot"]
            if hp not in ("cowrie", "dionaea", "conpot"):
                raise ValueError("Unsupported HoneyChart honeypot: " + hp)

            if hp not in honeypots:
                honeypots["names"].append(hp)
                honeypots[hp] = {
                    "volumes": [service["log_directory"]],
                    "services": [],
                    "containerports": [],
                    "protocols": [],
                }

            entry = honeypots[hp]
            if entry["volumes"] != [service["log_directory"]]:
                raise ValueError("Conflicting log directories for " + hp)

            entry["services"].append({
                service["service"]: service["service_port"]
            })
            entry["containerports"].append(service["container_port"])
            entry["protocols"].append(service["transport"].upper())

        requests.append({
            "release": name,
            "namespace": release["namespace"],
            "payload": {
                "name": name,
                "service": {
                    "type": release["service_type"],
                    "lbIp": None,
                },
                "replicaCount": 1,
                "honeypots": honeypots,
            },
        })
    return requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_directory", type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        plan = build_plan(args.evidence_directory, args.config)
        requests = make_requests(plan)

        folder = args.output.expanduser().resolve()
        folder.mkdir(parents=True, exist_ok=False)
        (folder / "deployment-plan.json").write_text(
            json.dumps(plan, indent=2) + "\n"
        )

        manifest = {
            "schema_version": 1,
            "status": "requests_generated",
            "deployment_ready": False,
            "requests": [],
        }
        for item in requests:
            filename = item["release"] + ".request.json"
            (folder / filename).write_text(
                json.dumps(item["payload"], indent=2) + "\n"
            )
            manifest["requests"].append({
                "release": item["release"],
                "namespace": item["namespace"],
                "file": filename,
            })
            print("Saved:", folder / filename)

        (folder / "request-manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )
        print("Requests generated; charts still require preparation and validation.")

    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()

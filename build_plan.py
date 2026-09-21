import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

# Mappings supported by the currently verified mixed deployment.
CATALOG = {
    ("cowrie", "ssh", "tcp", 22): 2222,
    ("dionaea", "http", "tcp", 80): 80,
}

parser = argparse.ArgumentParser()
parser.add_argument("profile", type=Path)
args = parser.parse_args()

try:
    profile = json.loads(args.profile.read_text())
    if profile.get("schema_version") != 2:
        raise ValueError("Expected profile schema version 2.")

    devices = profile["devices"]
    groups = {}
    review = []
    seen_ips = set()

    for device in devices:
        ip = device["ip"]
        if ip in seen_ips:
            raise ValueError("Repeated device IP: " + ip)
        seen_ips.add(ip)

        for item in device.get("unsupported_open_services", []):
            review.append({
                "ip": ip,
                "kind": "unmapped_open_service",
                "details": item,
            })

        seen_mappings = set()
        for recommendation in device.get("recommendations", []):
            port = recommendation["observed_port"]
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("Invalid observed port for " + ip)

            key = (
                recommendation["honeypot"],
                recommendation["service"],
                recommendation["transport"],
                port,
            )
            if key in seen_mappings:
                raise ValueError("Repeated recommendation for " + ip)
            seen_mappings.add(key)

            # Require the recommendation to have supporting scan evidence.
            supported = any(
                observation["state"] == "open"
                and observation["transport"] == key[2]
                and observation["port"] == port
                and observation["service"].get("name") == key[1]
                and observation["service"].get("method") == "probed"
                and not observation["service"].get("tunnel")
                for observation in device["observations"]
            )
            if not supported:
                raise ValueError(
                    "Recommendation lacks matching probe evidence: "
                    + ip + " " + str(key)
                )

            if key not in CATALOG:
                review.append({
                    "ip": ip,
                    "kind": "unsupported_deployment_mapping",
                    "details": recommendation,
                })
                continue

            group = groups.setdefault(key, {
                "honeypot": key[0],
                "service": key[1],
                "transport": key[2],
                "service_port": port,
                "container_port": CATALOG[key],
                "source_devices": [],
            })
            group["source_devices"].append(ip)

    services = []
    for key in sorted(groups):
        group = groups[key]
        group["source_devices"].sort()
        group["source_device_count"] = len(group["source_devices"])
        services.append(group)

    expected_mixed = set(CATALOG)
    if review:
        status = "review_required"
    elif not services:
        status = "no_supported_services"
    elif set(groups) == expected_mixed:
        status = "compatible_with_current_mixed_layout"
    else:
        status = "deployment_layout_change_required"

    plan = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_profile": str(args.profile.resolve()),
        "policy": "shared-service-honeypots-v1",
        "status": status,
        "candidate_release": "auto-mixed-01",
        "profiled_device_count": len(devices),
        "planned_service_count": len(services),
        "services": services,
        "review_items": review,
        "notes": [
            "Source devices explain selection; they are not traffic destinations.",
            "Shared honeypots emulate services, not individual device identities.",
            "Only services covered by the supplied scan are considered.",
            "This plan does not deploy, remove, or verify running services.",
        ],
    }

except (OSError, ValueError, KeyError, TypeError) as exc:
    parser.exit(1, "Error: {}\n".format(exc))

print(json.dumps(plan, indent=2))

import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from reconcile_profiles import reconcile


def valid_name(value):
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 53
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", value)
    )


def build_plan(evidence, config_path):
    profile = reconcile(evidence)
    config = json.loads(config_path.read_text())
    if config.get("schema_version") != 1:
        raise ValueError("Unsupported deployment configuration schema.")
    if not valid_name(config.get("namespace")):
        raise ValueError("Invalid namespace.")
    if config.get("service_type") != "NodePort":
        raise ValueError("This planner currently supports NodePort Services.")

    log_root = Path(config["log_root"])
    if not log_root.is_absolute() or ".." in log_root.parts:
        raise ValueError("log_root must be an absolute path without '..'.")

    mappings = {}
    for item in config["mappings"]:
        for field in ("honeypot", "service"):
            if not valid_name(item.get(field)):
                raise ValueError("Invalid mapping field: " + field)
        if item.get("transport") != "tcp":
            raise ValueError("This planner currently supports TCP mappings.")
        if not valid_name(item.get("release")):
            raise ValueError("Invalid release name.")
        for field in ("service_port", "container_port"):
            port = item.get(field)
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("Invalid " + field)

        key = (item["honeypot"], item["service"], item["transport"])
        if key in mappings:
            raise ValueError("Duplicate deployment mapping: " + str(key))
        mappings[key] = item

    groups = {}
    review = list(profile["review_items"])

    for device in profile["devices"]:
        for recommendation in device["recommendations"]:
            key = (
                recommendation["honeypot"],
                recommendation["service"],
                recommendation["transport"],
            )
            mapping = mappings.get(key)
            if mapping is None:
                review.append({
                    "ip": device["ip"],
                    "reason": "No deployment mapping for the recommendation.",
                    "recommendation": recommendation,
                })
                continue

            group = groups.setdefault(key, {
                **mapping,
                "log_directory": str(
                    log_root / mapping["release"] / mapping["honeypot"]
                ),
                "source_endpoints": [],
            })
            group["source_endpoints"].append({
                "ip": device["ip"],
                "observed_port": recommendation["observed_port"],
                "observation_index": recommendation["observation_index"],
                "source_index": recommendation["supporting_source_index"],
            })

    releases = {}
    for key in sorted(groups):
        group = groups[key]
        group["source_endpoints"].sort(
            key=lambda item: (item["ip"], item["observed_port"])
        )
        group["source_devices"] = sorted({
            item["ip"] for item in group["source_endpoints"]
        })
        group["source_device_count"] = len(group["source_devices"])
        release = releases.setdefault(group["release"], {
            "name": group["release"],
            "namespace": config["namespace"],
            "service_type": config["service_type"],
            "services": [],
        })
        release["services"].append(group)

    # HoneyChart places the selected containers in a shared Pod.
    # Refuse ambiguous Service names or overlapping container listeners.
    for release in releases.values():
        names = set()
        service_ports = set()
        container_ports = set()
        for service in release["services"]:
            name = service["service"]
            exposed = (service["transport"], service["service_port"])
            listener = (service["transport"], service["container_port"])
            if (
                name in names
                or exposed in service_ports
                or listener in container_ports
            ):
                raise ValueError(
                    "Conflicting service mapping in release " + release["name"]
                )
            names.add(name)
            service_ports.add(exposed)
            container_ports.add(listener)

    if review:
        status = "review_required"
    elif not groups:
        status = "no_supported_services"
    else:
        status = "planned"

    return {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": "shared-protocol-services-v2",
        "status": status,
        "deployment_ready": False,
        "evidence_directory": str(evidence.resolve()),
        "deployment_config": str(config_path.resolve()),
        "deployment_config_sha256": hashlib.sha256(
            config_path.read_bytes()
        ).hexdigest(),
        "sources": profile["sources"],
        "profiled_device_count": len(profile["devices"]),
        "planned_service_count": len(groups),
        "releases": [releases[name] for name in sorted(releases)],
        "review_items": review,
        "notes": [
            "This plan does not modify running deployments.",
            "Source endpoints explain selection; they are not traffic destinations.",
            "Observed ports and deployment ports are separate.",
            "Chart preparation and validation are required before deployment.",
            "Omitted services or releases are not instructions to delete them.",
            "Only listeners listed in these mappings are checked for collisions.",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_directory", type=Path)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = build_plan(args.evidence_directory, args.config)
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as exc:
        parser.exit(1, f"Error: {exc}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

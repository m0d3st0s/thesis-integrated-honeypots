import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from profiler import profile_scan

RULES = {
    ("tcp", "ssh"): "cowrie",
    ("tcp", "http"): "dionaea",
}


def profile_scan_v2(scan_path):
    result = profile_scan(scan_path)
    result["schema_version"] = 2
    result["selection_policy"] = "probed-services-v1"

    for device in result["devices"]:
        recommendations = []
        unsupported = []
        detected = set()
        open_count = 0

        for observation in device["observations"]:
            if observation["state"] != "open":
                continue

            open_count += 1
            service = observation["service"]
            name = service.get("name", "unknown")
            transport = observation["transport"]
            honeypot = RULES.get((transport, name))

            if service.get("method") != "probed":
                reason = "Service identity was not confirmed by probing"
            elif service.get("tunnel"):
                reason = "Tunneled services are not covered by these rules"
            elif honeypot is None:
                reason = "No honeypot mapping in the current catalog"
            else:
                detected.add(name)
                recommendations.append({
                    "honeypot": honeypot,
                    "service": name,
                    "observed_port": observation["port"],
                    "transport": transport,
                    "reason": f"Open {transport.upper()} service probed as {name}",
                    "fidelity": "Protocol emulation; not an exact device replica",
                })
                continue

            unsupported.append({
                "port": observation["port"],
                "transport": transport,
                "service": name,
                "reason": reason,
            })

        device["profile"] = (
            "+".join(sorted(detected)) + "-enabled-host"
            if detected else "unclassified"
        )
        device["recommendations"] = recommendations
        device["unsupported_open_services"] = unsupported
        device["selection_coverage"] = {
            "observed_open_services": open_count,
            "mapped_services": len(recommendations),
            "unmapped_services": len(unsupported),
            "note": "Mapping coverage, not verified deployment coverage.",
        }

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan", type=Path)
    args = parser.parse_args()

    try:
        result = profile_scan_v2(args.scan)
    except (OSError, ET.ParseError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Error: {exc}\n")

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def profile_scan(scan_path):
    root = ET.parse(scan_path).getroot()
    if root.tag != "nmaprun":
        raise ValueError("Input is not an Nmap XML report.")

    profiles = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            continue

        observations = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            observations.append({
                "port": int(port.get("portid")),
                "transport": port.get("protocol"),
                "state": state.get("state") if state is not None else "unknown",
                "service": dict(service.attrib) if service is not None else {},
            })

        ssh_services = [
            item for item in observations
            if item["state"] == "open"
            and item["transport"] == "tcp"
            and item["service"].get("name") == "ssh"
            and item["service"].get("method") == "probed"
        ]

        recommendations = [
            {
                "honeypot": "cowrie",
                "service": "ssh",
                "observed_port": item["port"],
                "reason": "Open TCP service identified as SSH by Nmap probing",
            }
            for item in ssh_services
        ]

        profiles.append({
            "ip": address.get("addr"),
            "profile": "ssh-enabled-host" if ssh_services else "unclassified",
            "observations": observations,
            "recommendations": recommendations,
        })

    return {
        "schema_version": 1,
        "source_scan": str(scan_path.resolve()),
        "scan_started": root.get("start"),
        "scope_note": "Profiles reflect only ports covered by this scan.",
        "devices": profiles,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan", type=Path, help="Nmap XML report")
    args = parser.parse_args()

    try:
        result = profile_scan(args.scan)
    except (OSError, ET.ParseError, ValueError) as exc:
        parser.exit(1, f"Error: {exc}\n")

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

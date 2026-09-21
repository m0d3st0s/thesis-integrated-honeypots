import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from profiler_v3 import profile_scan


def reconcile(folder):
    folder = folder.resolve()
    manifest = json.loads((folder / "scan-manifest.json").read_text())
    if manifest.get("status") != "completed":
        raise ValueError("A completed discovery run is required.")

    entries = manifest["profiles"]
    if (
        not entries
        or entries[0]["kind"] != "general"
        or sum(item["kind"] == "general" for item in entries) != 1
        or any(item["kind"] not in ("general", "modbus") for item in entries)
    ):
        raise ValueError("Expected one general scan followed by protocol probes.")

    targets = manifest["discovered_targets"]
    if not targets or len(set(targets)) != len(targets):
        raise ValueError("Invalid discovered-target list.")

    catalog = folder / "service-catalog.json"
    devices = {}
    sources = []
    seen_files = set()

    for source_index, entry in enumerate(entries):
        filename = entry["source_xml"]
        if (
            not isinstance(filename, str)
            or Path(filename).name != filename
            or filename in seen_files
        ):
            raise ValueError("Invalid or repeated source filename.")
        seen_files.add(filename)
        path = folder / filename
        if path.resolve().parent != folder:
            raise ValueError("Source XML must remain inside the evidence folder.")

        profile = profile_scan(path, catalog)
        started = int(profile["scan_started"])
        finished = int(profile["scan_finished"])
        if finished < started:
            raise ValueError("Invalid scan timestamps.")

        sources.append({
            "file": filename,
            "kind": entry["kind"],
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "scan_started": started,
            "scan_finished": finished,
            "scan_coverage": profile["scan_coverage"],
        })

        scanned_ips = {device["ip"] for device in profile["devices"]}
        if not scanned_ips.issubset(targets):
            raise ValueError("Scan contains an undiscovered address.")
        if source_index == 0 and scanned_ips != set(targets):
            raise ValueError("General profile does not cover all discovered hosts.")
        if entry["kind"] == "modbus" and not scanned_ips:
            raise ValueError("Protocol probe has no host observations.")

        for device in profile["devices"]:
            ip = device["ip"]
            if source_index == 0:
                devices[ip] = {
                    "ip": ip,
                    "device_type": "undetermined",
                    "observations": [],
                    "endpoints": {},
                    "summarized_port_states": device["summarized_port_states"],
                }

            combined = devices[ip]
            recommendations = {
                item["observation_index"]: item
                for item in device["recommendations"]
            }
            unsupported = {
                item["observation_index"]: item
                for item in device["unsupported_open_services"]
            }

            if entry["kind"] == "modbus" and not device["observations"]:
                raise ValueError("Protocol probe has no explicit port observations.")

            for index, observation in enumerate(device["observations"]):
                key = (observation["transport"], observation["port"])
                histories = combined["endpoints"]
                if source_index != 0:
                    if key not in histories:
                        raise ValueError("Probe endpoint absent from the general scan.")
                    first = combined["observations"][histories[key][0]]
                    if first["state"] != "open":
                        raise ValueError("Protocol probe targeted a non-open endpoint.")
                    previous = combined["observations"][histories[key][-1]]
                    prior_source = sources[previous["source_index"]]
                    if started < prior_source["scan_finished"]:
                        raise ValueError("Overlapping or unordered endpoint scans.")

                recommendation = recommendations.get(index)
                if (
                    entry["kind"] == "modbus"
                    and recommendation is not None
                    and recommendation["service"] != "modbus"
                ):
                    raise ValueError("Unexpected recommendation from a Modbus probe.")

                observation_index = len(combined["observations"])
                combined["observations"].append({
                    **observation,
                    "source_index": source_index,
                    "candidate": recommendation,
                    "unmapped_reason": unsupported.get(index, {}).get("reason"),
                })
                histories.setdefault(key, []).append(observation_index)

    review_items = []
    output_devices = []
    for ip, device in devices.items():
        recommendations = []
        unresolved = []
        endpoints = []

        for (transport, port), indices in sorted(device["endpoints"].items()):
            history = [device["observations"][i] for i in indices]
            latest = history[-1]
            confirmed = {
                (
                    item["service"].get("name"),
                    item["service"].get("tunnel"),
                )
                for item in history
                if item["state"] == "open"
                and item["service"].get("method") == "probed"
            }
            states = {item["state"] for item in history}
            reason = None
            if len(states) > 1:
                reason = "Endpoint state changed between observations."
            elif len(confirmed) > 1:
                reason = "Confirmed protocol identifications conflict."
            elif latest["state"] not in ("open", "closed"):
                reason = "Latest endpoint state is unresolved."
            elif latest["state"] == "open" and latest["candidate"] is None:
                reason = latest["unmapped_reason"] or "No supported identification."

            endpoint = {
                "transport": transport,
                "port": port,
                "observation_indices": indices,
                "latest_observation_index": indices[-1],
                "status": "review_required" if reason else "resolved",
            }
            endpoints.append(endpoint)

            if reason:
                item = {
                    "ip": ip,
                    "transport": transport,
                    "port": port,
                    "reason": reason,
                    "observation_indices": indices,
                }
                unresolved.append(item)
                review_items.append(item)
            elif latest["state"] == "open":
                recommendation = dict(latest["candidate"])
                recommendation["observation_index"] = indices[-1]
                recommendation["supporting_source_index"] = latest["source_index"]
                recommendations.append(recommendation)

        protocols = sorted({item["service"] for item in recommendations})
        output_devices.append({
            "ip": ip,
            "device_type": "undetermined",
            "profile": (
                "+".join(protocols) + "-enabled-host"
                if protocols else "unclassified"
            ),
            "observations": device["observations"],
            "summarized_port_states": device["summarized_port_states"],
            "endpoints": endpoints,
            "recommendations": recommendations,
            "unresolved_endpoints": unresolved,
        })

    return {
        "schema_version": 4,
        "selection_policy": "reconciled-protocol-evidence-v1",
        "status": "review_required" if review_items else "ready_for_planning",
        "evidence_directory": str(folder),
        "catalog_sha256": hashlib.sha256(catalog.read_bytes()).hexdigest(),
        "sources": sources,
        "devices": output_devices,
        "review_items": review_items,
        "notes": [
            "Ready for planning does not mean approved for deployment.",
            "Observations were collected at different times.",
            "Confirmed protocols do not establish physical device types.",
            "Only scanned ports and responding devices are represented.",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_directory", type=Path)
    args = parser.parse_args()
    try:
        result = reconcile(args.evidence_directory)
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as exc:
        parser.exit(1, f"Error: {exc}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

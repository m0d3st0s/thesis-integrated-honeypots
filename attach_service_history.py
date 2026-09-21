import argparse
import copy
import json
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("report_dir", type=Path)
parser.add_argument("--history-root", type=Path, required=True)
parser.add_argument("--namespace")
args = parser.parse_args()

def parse_time(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamp has no timezone.")
    return result.astimezone(timezone.utc)

try:
    report = json.loads(
        (args.report_dir / "window-feed.json").read_text()
    )
    if report.get("schema_version") != 1:
        raise ValueError("Unsupported report schema.")

    observations = []
    namespaces = set()
    paths = sorted(
        set(args.history_root.rglob("service-state*.json"))
        | set(args.history_root.rglob("service-observation-*.json"))
    )
    for path in paths:
        record = json.loads(path.read_text())

        # New deployer format: timestamped observation containing raw Service.
        if path.name.startswith("service-observation-"):
            service = record["service"]
            metadata = service["metadata"]
            if service.get("kind") != "Service":
                raise ValueError("Expected a Service: " + str(path))
            if (
                metadata["name"] != record["release"]
                or metadata["namespace"] != record["namespace"]
            ):
                raise ValueError("Service identity mismatch: " + str(path))
            record = {
                "schema_version": 1,
                "release": record["release"],
                "namespace": record["namespace"],
                "phase": record["phase"],
                "observation_started_at": record["observation_started_at"],
                "observation_finished_at": record["observation_finished_at"],
                "service_uid": metadata["uid"],
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
            }
        if record.get("schema_version") != 1:
            raise ValueError("Unsupported history schema: " + str(path))
        identifiers = [
            record[key]
            for key in ("deployment", "release")
            if key in record
        ]
        if not identifiers or any(
            not isinstance(value, str) or not value.strip()
            for value in identifiers
        ):
            raise ValueError("Missing or invalid release identifier: " + str(path))
        if len(set(identifiers)) != 1:
            raise ValueError("Conflicting release identifiers: " + str(path))
        if identifiers[0] != report["deployment"]:
            continue

        namespace = record.get("namespace")
        if not isinstance(namespace, str) or not namespace:
            raise ValueError("Missing history namespace: " + str(path))
        requested_namespace = args.namespace or report.get("namespace")
        if requested_namespace and namespace != requested_namespace:
            continue
        namespaces.add(namespace)

        start = parse_time(record["observation_started_at"])
        finish = parse_time(record["observation_finished_at"])
        if finish < start:
            raise ValueError("Invalid observation interval: " + str(path))

        observations.append({
            "source_file": str(path.resolve()),
            "namespace": namespace,
            "phase": record["phase"],
            "observation_started_at": record["observation_started_at"],
            "observation_finished_at": record["observation_finished_at"],
            "service_uid": record["service_uid"],
            "ports": record["ports"],
        })

    if len(namespaces) > 1:
        raise ValueError("Multiple namespaces match; specify --namespace.")

    observations.sort(
        key=lambda item: parse_time(item["observation_finished_at"])
    )

    output = copy.deepcopy(report)
    without_prior = 0

    for event in output["connections"]:
        timestamp = parse_time(event["timestamp"])
        earlier = [
            item for item in observations
            if parse_time(item["observation_finished_at"]) <= timestamp
        ]
        latest = earlier[-1] if earlier else None

        matches = []
        if latest:
            matches = [
                port for port in latest["ports"]
                if port["name"] == event.get("service")
                and port["transport"].lower() == event.get("transport", "").lower()
                and port["target_port"] == event.get("local_port")
            ]
        else:
            without_prior += 1

        event["mapping_context"] = {
            "recorded_local_port": event.get("local_port"),
            "external_destination_port": None,
            "external_destination_port_status": "not_observed_in_source_record",
            "latest_prior_configuration_observation": latest,
            "matching_ports_in_that_observation": matches,
            "historical_mapping_status": (
                "prior_configuration_available_but_event_mapping_unverified"
                if latest else "no_prior_timestamped_configuration"
            ),
        }

    output["mapping_history"] = {
        "annotated_at": datetime.now(timezone.utc).isoformat(),
        "observation_count": len(observations),
        "connections_without_prior_observation": without_prior,
        "observations": observations,
        "limitations": [
            "Configuration observations do not prove continuous availability.",
            "A prior configuration may have changed before an event.",
            "Observations after an event are not assigned retrospectively.",
            "Untimestamped legacy Service snapshots are not used for time attribution.",
            "Honeypot local ports are not assumed to be external NodePorts.",
        ],
    }

    destination = args.report_dir / "window-feed-with-history.json"
    with destination.open("x") as target:
        json.dump(output, target, indent=2)
        target.write("\n")

except (OSError, ValueError, KeyError, TypeError) as exc:
    parser.exit(1, "Error: {}\n".format(exc))

print("Saved:", destination)
print("Timestamped configuration observations:", len(observations))
print("Connections without a prior observation:", without_prior)
print("External destination ports remain unverified from these source records.")

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--cowrie", required=True, type=Path)
parser.add_argument("--dionaea", required=True, type=Path)
parser.add_argument("--deployment", required=True)
parser.add_argument("--test-event", action="append", default=[])
args = parser.parse_args()


def read_jsonl(path):
    with path.open() as stream:
        for number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON: {path}, line {number}") from exc


try:
    events = list(read_jsonl(args.dionaea))

    for raw in read_jsonl(args.cowrie):
        if raw.get("eventid") != "cowrie.session.connect":
            continue

        timestamp = datetime.fromisoformat(
            raw["timestamp"].replace("Z", "+00:00")
        )
        if timestamp.tzinfo is None:
            raise ValueError("Cowrie timestamp has no timezone.")

        events.append({
            "schema_version": 1,
            "honeypot": "cowrie",
            "deployment": args.deployment,
            "event_id": f"cowrie:{raw['sensor']}:{raw['session']}:connect",
            "event_type": "connection_observed",
            "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
            "timestamp_meaning": "connection_start",
            "connection_id": raw["session"],
            "sensor": raw["sensor"],
            "connection_type": "accept",
            "transport": "tcp",
            "service": raw["protocol"],
            "original_protocol": raw["protocol"],
            "local_ip": raw["dst_ip"],
            "local_port": raw["dst_port"],
            "remote_ip": raw["src_ip"],
            "remote_port": raw["src_port"],
            "count_as_inbound_connection": True,
            "classification": "unclassified",
        })

    unique = {}
    for event in events:
        if event["deployment"] != args.deployment:
            raise ValueError("Input contains another deployment.")
        event_id = event["event_id"]
        if event_id in unique and unique[event_id] != event:
            raise ValueError(f"Conflicting records for {event_id}")
        unique[event_id] = event

    test_ids = set(args.test_event)
    for event_id, event in unique.items():
        if event_id in test_ids:
            event["classification"] = "controlled_test"

    inbound = [
        event for event in unique.values()
        if event["count_as_inbound_connection"]
    ]

    rows = []
    services = sorted({event["service"] or "unknown" for event in inbound})
    for service in services:
        selected = [
            event for event in inbound
            if (event["service"] or "unknown") == service
        ]
        classifications = Counter(
            event["classification"] for event in selected
        )
        rows.append({
            "service": service,
            "incoming_connections": len(selected),
            "controlled_test_connections": classifications["controlled_test"],
            "unclassified_connections": classifications["unclassified"],
            "observed_remote_ips": sorted({
                event["remote_ip"] for event in selected
            }),
        })

    report = {
        "schema_version": 1,
        "deployment": args.deployment,
        "scope": "All connection-start records in the supplied snapshots.",
        "metric": "Incoming connections, not log lines or HTTP requests.",
        "duplicate_records_removed": len(events) - len(unique),
        "total_incoming_connections": len(inbound),
        "by_service": rows,
        "connections": sorted(
            inbound, key=lambda event: event["timestamp"]
        ),
    }

except (OSError, ValueError, KeyError, TypeError) as exc:
    parser.exit(1, f"Comparison failed: {exc}\n")

print(json.dumps(report, indent=2))

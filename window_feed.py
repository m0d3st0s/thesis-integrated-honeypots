import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

def parse_time(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamps must include a timezone.")
    return result.astimezone(timezone.utc)

parser = argparse.ArgumentParser()
parser.add_argument("feed", type=Path)
parser.add_argument("--since", required=True)
parser.add_argument("--until", required=True)
args = parser.parse_args()

try:
    since = parse_time(args.since)
    until = parse_time(args.until)
    if since >= until:
        raise ValueError("--since must be earlier than --until.")

    source = json.loads(args.feed.read_text())
    if source.get("schema_version") != 1:
        raise ValueError("Unsupported feed schema.")

    connections = []
    seen = set()

    for event in source["connections"]:
        event_id = event["event_id"]
        if event_id in seen:
            raise ValueError("Duplicate event ID in input: " + event_id)
        seen.add(event_id)

        if event.get("count_as_inbound_connection") is not True:
            continue

        timestamp = parse_time(event["timestamp"])
        if since <= timestamp < until:
            connections.append(event)

    connections.sort(key=lambda event: parse_time(event["timestamp"]))

    groups = {}
    for event in connections:
        service = event.get("service") or "unknown"
        group = groups.setdefault(service, {
            "service": service,
            "incoming_connections": 0,
            "controlled_test_connections": 0,
            "unclassified_connections": 0,
            "observed_remote_ips": set(),
        })

        classification = event.get("classification", "unclassified")
        if classification not in ("controlled_test", "unclassified"):
            raise ValueError("Unsupported classification: " + classification)

        group["incoming_connections"] += 1
        key = (
            "controlled_test_connections"
            if classification == "controlled_test"
            else "unclassified_connections"
        )
        group[key] += 1

        if event.get("remote_ip"):
            group["observed_remote_ips"].add(event["remote_ip"])

    by_service = list(groups.values())
    for group in by_service:
        group["observed_remote_ips"] = sorted(group["observed_remote_ips"])

    by_service.sort(
        key=lambda group: (-group["incoming_connections"], group["service"])
    )

    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_feed": str(args.feed.resolve()),
        "source_feed_generated_at": source.get("generated_at"),
        "deployment": source["deployment"],
        "window": {
            "since_inclusive": since.isoformat(),
            "until_exclusive": until.isoformat(),
        },
        "scope": "Connection starts within the window, from supplied snapshots.",
        "coverage_note": (
            "A requested window does not establish complete collection "
            "throughout that window."
        ),
        "metric": "Incoming connections, not HTTP requests or log lines.",
        "total_incoming_connections": len(connections),
        "by_service": by_service,
        "connections": connections,
    }

except (OSError, ValueError, KeyError, TypeError) as exc:
    parser.exit(1, "Error: {}\n".format(exc))

print(json.dumps(report, indent=2))

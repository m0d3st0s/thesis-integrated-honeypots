import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("log", type=Path)
parser.add_argument("--service", required=True, type=Path)
parser.add_argument("--test-session", action="append", default=[])
parser.add_argument("--since", help="Inclusive ISO timestamp with timezone")
parser.add_argument("--until", help="Exclusive ISO timestamp with timezone")
args = parser.parse_args()


def parse_timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamps must include Z or a timezone offset.")
    return result.astimezone(timezone.utc)


if bool(args.since) != bool(args.until):
    parser.error("Provide both --since and --until.")

try:
    since = parse_timestamp(args.since) if args.since else None
    until = parse_timestamp(args.until) if args.until else None
    if since is not None and since >= until:
        raise ValueError("--since must be earlier than --until.")
except ValueError as exc:
    parser.error(str(exc))


try:
    service = json.loads(args.service.read_text())
    ssh_port = next(
        port for port in service["spec"]["ports"]
        if port.get("name") == "ssh"
    )

    sessions = {}
    event_counts = Counter()
    timestamps = []

    with args.log.open() as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}") from exc

            timestamp = parse_timestamp(event["timestamp"])
            if since is not None and not (since <= timestamp < until):
                continue

            event_id = event.get("eventid", "unknown")
            event_counts[event_id] += 1
            if event.get("timestamp"):
                timestamps.append(timestamp.isoformat())

            session_id = event.get("session")
            if not session_id:
                continue

            key = (event.get("sensor", "unknown"), session_id)
            session = sessions.setdefault(key, {
                "sensor": key[0],
                "session_id": session_id,
                "classification": (
                    "controlled_test"
                    if session_id in args.test_session
                    else "unclassified"
                ),
                "source_ips": set(),
                "container_destination_ports": set(),
                "successful_logins": 0,
                "failed_logins": 0,
                "commands": [],
                "duration_seconds": None,
            })

            if event.get("src_ip"):
                session["source_ips"].add(event["src_ip"])
            if event_id == "cowrie.session.connect":
                if event.get("dst_port") is not None:
                    session["container_destination_ports"].add(event["dst_port"])
            elif event_id == "cowrie.login.success":
                session["successful_logins"] += 1
            elif event_id == "cowrie.login.failed":
                session["failed_logins"] += 1
            elif event_id == "cowrie.command.input":
                session["commands"].append(event.get("input", ""))
            elif event_id == "cowrie.session.closed":
                session["duration_seconds"] = event.get("duration")

    records = list(sessions.values())
    for record in records:
        record["source_ips"] = sorted(record["source_ips"])
        record["container_destination_ports"] = sorted(
            record["container_destination_ports"]
        )

    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": (
            "Events within the requested window, from the supplied snapshot."
            if since is not None
            else "All events in the supplied log snapshot; not a daily window."
        ),
        "window": {
            "since_inclusive": since.isoformat() if since else None,
            "until_exclusive": until.isoformat() if until else None,
        },
        "session_count_definition": "Distinct sessions with included events.",
        "duration_note": (
            "Duration is the full session duration reported by a close event, "
            "when that event is included; it is not clipped to the window."
        ),
        "first_event": min(timestamps) if timestamps else None,
        "last_event": max(timestamps) if timestamps else None,
        "deployment": {
            "release": service["metadata"]["name"],
            "namespace": service["metadata"]["namespace"],
            "service": "ssh",
            "service_port": ssh_port["port"],
            "node_port": ssh_port.get("nodePort"),
        },
        "raw_event_count": sum(event_counts.values()),
        "session_count": len(records),
        "controlled_test_sessions": sum(
            record["classification"] == "controlled_test" for record in records
        ),
        "unique_observed_source_ips": sorted({
            ip for record in records for ip in record["source_ips"]
        }),
        "event_counts": dict(event_counts),
        "sessions": records,
    }

except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
    parser.exit(1, f"Cannot build feed: {exc}\n")

print(json.dumps(report, indent=2))

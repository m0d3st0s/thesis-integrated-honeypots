import argparse
import hashlib
import ipaddress
import json
import os
import stat
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def export_log(path, deployment, log_id):
    with path.open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Expected a regular log file.")
        raw = source.read(before.st_size)
        after = os.fstat(source.fileno())

    current = path.stat()
    if (
        len(raw) != before.st_size
        or after.st_size < before.st_size
        or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
        or current.st_size < before.st_size
    ):
        raise ValueError("Log changed identity or was truncated; rerun.")

    end = raw.rfind(b"\n") + 1
    complete = raw[:end]
    events = []
    offset = 0

    for number, line in enumerate(complete.splitlines(keepends=True), 1):
        start = offset
        offset += len(line)
        if not line.strip():
            continue

        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError(f"Expected a JSON object at line {number}.")
        if event["sensorid"] != deployment:
            raise ValueError(f"Unexpected sensor at line {number}.")
        if event["data_type"] != "modbus":
            raise ValueError(f"Unexpected protocol at line {number}.")
        if not isinstance(event["id"], str) or not event["id"]:
            raise ValueError(f"Missing session ID at line {number}.")

        timestamp = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )
        timezone_basis = "explicit_offset"
        if timestamp.tzinfo is None:
            # Verified AttackSession source in the pinned image uses utcnow().
            timestamp = timestamp.replace(tzinfo=timezone.utc)
            timezone_basis = "UTC_from_verified_Conpot_image_source"
        timestamp = timestamp.astimezone(timezone.utc)

        for field in ("src_ip", "dst_ip"):
            ipaddress.ip_address(event[field])
        for field in ("src_port", "dst_port"):
            value = event[field]
            if type(value) is not int or not 1 <= value <= 65535:
                raise ValueError(f"Invalid {field} at line {number}.")

        for field in ("request", "response"):
            value = event.get(field)
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"Invalid {field} at line {number}.")
                if len(value) % 2 or any(
                    character not in "0123456789abcdefABCDEF"
                    for character in value
                ):
                    raise ValueError(f"Invalid hexadecimal {field} at line {number}.")

        event_type = event.get("event_type")
        if event_type is not None and not isinstance(event_type, str):
            raise ValueError(f"Invalid event type at line {number}.")

        digest = hashlib.sha256(line).hexdigest()
        events.append({
            "event_id": f"conpot:{log_id}:{start}:{digest}",
            "honeypot": "conpot",
            "deployment": deployment,
            "service": "modbus",
            "transport": "tcp",
            "session_id": event["id"],
            "reported_session_started_at": timestamp.isoformat(),
            "timestamp_meaning": "session_creation_not_individual_event_time",
            "timezone_basis": timezone_basis,
            "event_type": event_type,
            "is_connection_start_record": event_type == "NEW_CONNECTION",
            "remote_ip": event["src_ip"],
            "remote_port": event["src_port"],
            "local_ip": event["dst_ip"],
            "local_port": event["dst_port"],
            "endpoint_meaning": "session_metadata_may_be_reused",
            "request_hex": event.get("request"),
            "response_hex": event.get("response"),
            "classification": "unclassified",
            "source_line": number,
            "source_byte_offset": start,
            "source_record_sha256": digest,
            "raw_record": event,
        })

    counts = Counter(
        item["event_type"] if item["event_type"] is not None else "UNSPECIFIED"
        for item in events
    )
    start_count = sum(item["is_connection_start_record"] for item in events)

    return {
        "schema_version": 1,
        "report_kind": "conpot_record_evidence",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "deployment": deployment,
        "source_log": str(path.resolve()),
        "log_id": log_id,
        "source_bytes_read": len(raw),
        "source_bytes_included": len(complete),
        "trailing_bytes_omitted": len(raw) - end,
        "included_sha256": hashlib.sha256(complete).hexdigest(),
        "total_records": len(events),
        "connection_start_records": start_count,
        "payload_records": sum(
            item["request_hex"] is not None or item["response_hex"] is not None
            for item in events
        ),
        "by_event_type": dict(counts),
        "limitations": [
            "Counts logged NEW_CONNECTION records, not independently verified TCP connections.",
            "Session IDs may be reused; records are not deduplicated by session ID.",
            "Timestamps and endpoints originate from session metadata.",
            "Exact individual-event timing is unavailable in this log format.",
            "Only the supplied file prefix is included; no full-window coverage is established.",
            "Record IDs require the same log_id and an unchanged append-only file prefix.",
            "Use a new log_id after truncation or replacement; rotation is not collected automatically.",
            "Controlled-test classification requires explicit evidence-based labels.",
        ],
        "events": events,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--log-id", required=True)
    args = parser.parse_args()
    try:
        result = export_log(args.log, args.deployment, args.log_id)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Export failed: {exc}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

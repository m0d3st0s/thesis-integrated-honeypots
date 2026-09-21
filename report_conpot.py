import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def parse_time(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamps must include a timezone.")
    return result.astimezone(timezone.utc)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--labels", required=True, type=Path)
    parser.add_argument("--since", required=True)
    parser.add_argument("--until", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        since = parse_time(args.since)
        until = parse_time(args.until)
        if since >= until:
            raise ValueError("SINCE must be earlier than UNTIL.")

        evidence_bytes = args.evidence.read_bytes()
        label_bytes = args.labels.read_bytes()
        source = json.loads(evidence_bytes)
        labels = json.loads(label_bytes)

        if (
            source.get("schema_version") != 1
            or source.get("report_kind") != "conpot_record_evidence"
            or labels.get("schema_version") != 1
        ):
            raise ValueError("Unsupported evidence or label format.")

        events = {}
        for event in source["events"]:
            event_id = event["event_id"]
            if event_id in events:
                raise ValueError("Duplicate record ID: " + event_id)
            if event["deployment"] != source["deployment"]:
                raise ValueError("Evidence contains another deployment.")
            if (
                event.get("timestamp_meaning")
                != "session_creation_not_individual_event_time"
            ):
                raise ValueError("Unexpected timestamp meaning.")
            if type(event.get("is_connection_start_record")) is not bool:
                raise ValueError("Invalid connection-start flag.")
            if event["is_connection_start_record"] != (
                event["event_type"] == "NEW_CONNECTION"
            ):
                raise ValueError("Connection-start flag disagrees with event type.")
            parse_time(event["reported_session_started_at"])
            events[event_id] = dict(event, classification="unclassified")

        seen_labels = set()
        unmatched_labels = []
        for label in labels["events"]:
            event_id = label["event_id"]
            if event_id in seen_labels:
                raise ValueError("Duplicate test label: " + event_id)
            seen_labels.add(event_id)
            if (
                label["deployment"] != source["deployment"]
                or label["classification"] != "controlled_test"
            ):
                raise ValueError("Unexpected deployment or classification in label.")

            event = events.get(event_id)
            if event is None:
                unmatched_labels.append(event_id)
                continue
            if not event["is_connection_start_record"]:
                raise ValueError("A test-start label points to a non-start record.")

            payload = events.get(label["supporting_payload_event_id"])
            if payload is None:
                raise ValueError("Supporting payload record is missing.")
            for key in (
                "deployment", "session_id", "remote_ip", "remote_port",
                "local_ip", "local_port",
            ):
                if event[key] != payload[key]:
                    raise ValueError("Supporting payload has different session metadata.")

            client = label["client_evidence"]
            if (
                client["source_ip"] != event["remote_ip"]
                or client["source_port"] != event["remote_port"]
                or client["request_hex"] != payload["request_hex"]
                or client["response_payload_hex"] != payload["response_hex"]
            ):
                raise ValueError("Test label does not match the recorded exchange.")

            event["classification"] = "controlled_test"

        selected = [
            event for event in events.values()
            if since <= parse_time(event["reported_session_started_at"]) < until
        ]
        selected.sort(key=lambda event: (
            parse_time(event["reported_session_started_at"]),
            event["source_byte_offset"],
        ))

        starts = [
            event for event in selected
            if event["is_connection_start_record"]
        ]
        controlled = sum(
            event["classification"] == "controlled_test" for event in starts
        )
        payload_count = sum(
            event["request_hex"] is not None or event["response_hex"] is not None
            for event in selected
        )

        report = {
            "schema_version": 1,
            "report_kind": "conpot_window_evidence",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "deployment": source["deployment"],
            "window": {
                "since_inclusive": since.isoformat(),
                "until_exclusive": until.isoformat(),
                "basis": "reported_session_creation_time",
            },
            "metric": "Logged NEW_CONNECTION records, not verified TCP connections.",
            "records_in_window": len(selected),
            "connection_start_records": len(starts),
            "controlled_test_start_records": controlled,
            "unclassified_start_records": len(starts) - controlled,
            "payload_records": payload_count,
            "unmatched_label_ids": unmatched_labels,
            "source_evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
            "source_labels_sha256": hashlib.sha256(label_bytes).hexdigest(),
            "limitations": source["limitations"] + [
                "Window membership uses session creation time, not individual event time.",
                "Later activity in a reused session may fall outside its actual event-time window.",
                "Payload records are not automatically classified from a session ID.",
            ],
            "events": selected,
        }

        lines = [
            "CONPOT MODBUS EVIDENCE REPORT",
            "Deployment: " + source["deployment"],
            "Since (inclusive): " + since.isoformat(),
            "Until (exclusive): " + until.isoformat(),
            "Window basis: reported session creation time.",
            "Coverage: supplied evidence only; full-window coverage is not established.",
            "",
            "Logged connection starts: " + str(len(starts)),
            "Controlled-test starts: " + str(controlled),
            "Unclassified starts: " + str(len(starts) - controlled),
            "Records containing payloads: " + str(payload_count),
            "Total log records in window: " + str(len(selected)),
            "Labels absent from supplied evidence: " + str(len(unmatched_labels)),
            "",
            "These are logged start records, not independently verified TCP connections.",
            "Session timestamps and endpoints may be reused.",
            "Unclassified does not mean malicious.",
            "These metrics remain separate from the SSH/HTTP connection totals.",
        ]
        text = "\n".join(lines) + "\n"

        folder = args.output.expanduser().resolve()
        folder.mkdir(parents=True, exist_ok=False)
        (folder / "source-evidence.json").write_bytes(evidence_bytes)
        (folder / "controlled-test-labels.json").write_bytes(label_bytes)
        (folder / "modbus-report.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        (folder / "report.txt").write_text(text)

        print(text)
        print("Report saved:", folder)

    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Report failed: {exc}\n")


if __name__ == "__main__":
    main()

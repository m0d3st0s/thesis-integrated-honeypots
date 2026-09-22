import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from protocol_support import dionaea_service

parser = argparse.ArgumentParser()
parser.add_argument("database", type=Path)
parser.add_argument("--database-id", required=True)
parser.add_argument("--deployment", required=True)
args = parser.parse_args()

db = None
try:
    db = sqlite3.connect(
        args.database.resolve().as_uri() + "?mode=ro",
        uri=True,
    )
    db.row_factory = sqlite3.Row

    rows = db.execute("""
        SELECT connection, connection_type, connection_transport,
               connection_protocol, connection_timestamp,
               local_host, local_port, remote_host, remote_port
        FROM connections
        ORDER BY connection
    """)

    events = []
    for row in rows:
        timestamp = datetime.fromtimestamp(
            row["connection_timestamp"], timezone.utc
        ).isoformat()

        connection_id = row["connection"]
        inbound = row["connection_type"] == "accept"
        service = dionaea_service(row["connection_protocol"], row["connection_transport"])

        events.append({
            "schema_version": 1,
            "honeypot": "dionaea",
            "deployment": args.deployment,
            "database_id": args.database_id,
            "event_id": (
                f"dionaea:{args.database_id}:connection:{connection_id}"
            ),
            "event_type": "connection_observed",
            "timestamp": timestamp,
            "timestamp_meaning": "connection_start",
            "connection_id": connection_id,
            "connection_type": row["connection_type"],
            "transport": row["connection_transport"],
            "service": service,
            "original_protocol": row["connection_protocol"],
            "service_identification": "recorded_protocol_and_transport" if service else "unrecognized_protocol_or_transport",
            "local_ip": row["local_host"],
            "local_port": row["local_port"],
            "remote_ip": row["remote_host"],
            "remote_port": row["remote_port"],
            "count_as_inbound_connection": inbound,
            "classification": "unclassified",
        })

except (OSError, sqlite3.Error, ValueError, OverflowError) as exc:
    parser.exit(1, f"Export failed: {exc}\n")
finally:
    if db is not None:
        db.close()

for event in events:
    print(json.dumps(event))

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from export_conpot import export_log


def now():
    return datetime.now(timezone.utc).isoformat()


def parse_time(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamps must include a timezone.")
    return result.astimezone(timezone.utc)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def snapshot_log(source, destination):
    started = now()
    with source.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Conpot log must be a regular file.")
        raw = stream.read(before.st_size)
        after = os.fstat(stream.fileno())

    current = source.stat()
    if (
        len(raw) != before.st_size
        or after.st_size < before.st_size
        or current.st_size < before.st_size
        or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise ValueError("Conpot log rotated or was truncated; rerun.")

    destination.write_bytes(raw)
    return {
        "source": str(source.resolve()),
        "started_at": started,
        "finished_at": now(),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "device": before.st_dev,
        "inode": before.st_ino,
        "note": "Captured file prefix; later appends are excluded.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("since")
    parser.add_argument("until")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--skip-mixed", action="store_true")
    parser.add_argument("--skip-conpot", action="store_true")
    parser.add_argument("--mixed-services", default="cowrie,dionaea")
    parser.add_argument('--mixed-protocols')
    parser.add_argument("--conpot-log", type=Path)
    parser.add_argument("--conpot-deployment")
    parser.add_argument("--conpot-namespace")
    parser.add_argument("--conpot-log-id")
    parser.add_argument("--conpot-labels", type=Path)
    mixed_options = ("deployment", "namespace", "database", "database-id",
                     "cowrie-log", "labels", "history-root", "reports-root")
    for option in mixed_options:
        parser.add_argument("--mixed-" + option)
    args = parser.parse_args()
    if args.skip_mixed and args.skip_conpot:
        parser.error("At least one reporting section must be selected.")
    if not args.skip_conpot and not all((args.conpot_log, args.conpot_deployment,
                                       args.conpot_namespace, args.conpot_log_id, args.conpot_labels)):
        parser.error("Selected Conpot section requires all --conpot-* settings.")
    supplied = [getattr(args, "mixed_" + option.replace("-", "_"))
                for option in mixed_options]
    if any(value is not None for value in supplied) and not all(supplied):
        parser.error("Supply all --mixed-* settings together.")
    mixed_arguments = [argument for option, value in zip(mixed_options, supplied)
                       if value is not None for argument in ("--" + option, value)]

    try:
        if parse_time(args.since) >= parse_time(args.until):
            raise ValueError("SINCE must be earlier than UNTIL.")
        os.umask(0o077)
        project = Path(__file__).resolve().parent
        folder = args.output.expanduser().resolve()
        folder.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Error: {exc}\n")

    manifest = {
        "schema_version": 1,
        "started_at": now(),
        "status": "running",
        "window_requested": {
            "since": args.since,
            "until": args.until,
        },
        "sections": {
            "ssh_http": {"status": "pending"},
            "modbus": {"status": "pending"},
        },
        "limitations": [
            "Sections are collected sequentially, not atomically.",
            "Mixed-service connection counts and Modbus logged starts are separate metrics.",
            "The legacy ssh_http section key and ssh-http folder now also hold HTTPS/SMB.",
            "A requested window does not establish continuous collection coverage.",
            "Conpot window membership uses reported session creation time.",
            "Conpot log identity must change after source replacement or truncation.",
        ],
    }

    def save_manifest():
        write_json(folder / "collection-manifest.json", manifest)

    def run_logged(command, log_path):
        with log_path.open("w") as output:
            subprocess.run(
                command, stdout=output, stderr=subprocess.STDOUT,
                check=True, timeout=600,
            )

    def capture_json(command, path):
        result = subprocess.run(
            command, capture_output=True, text=True,
            check=True, timeout=60,
        )
        write_json(path, json.loads(result.stdout))

    def mixed():
        run_logged([
            "bash", str(project / "collect_report.sh"),
            args.since, args.until,
            "--output", str(folder / "ssh-http"),
        ] + mixed_arguments + ["--services", args.mixed_services]
            + (['--protocols', args.mixed_protocols] if args.mixed_protocols else []), folder / "ssh-http-collector.log")
        if not (folder / "ssh-http/report-completed.txt").is_file():
            raise ValueError("Mixed-service completion marker is missing.")

    def modbus():
        section = folder / "modbus"
        section.mkdir()
        metadata = {
            "deployment": args.conpot_deployment,
            "namespace": args.conpot_namespace,
            "metadata_started_at": now(),
            "mapping_note": (
                "Service metadata describes collection time, "
                "not verified historical event destinations."
            ),
        }
        capture_json([
            "kubectl", "get", "service", args.conpot_deployment,
            "-n", args.conpot_namespace, "-o", "json",
        ], section / "service.json")
        capture_json([
            "kubectl", "get", "pods",
            "-n", args.conpot_namespace,
            "-l", "app.kubernetes.io/instance=" + args.conpot_deployment,
            "-o", "json",
        ], section / "pods.json")
        metadata["metadata_finished_at"] = now()

        snapshot = section / "conpot-snapshot.jsonl"
        metadata["snapshot"] = snapshot_log(
            args.conpot_log.expanduser(), snapshot
        )
        labels = section / "controlled-test-labels.json"
        labels.write_bytes(args.conpot_labels.expanduser().read_bytes())

        evidence = export_log(
            snapshot, args.conpot_deployment, args.conpot_log_id
        )
        evidence_path = section / "conpot-evidence.json"
        write_json(evidence_path, evidence)
        write_json(section / "collection.json", metadata)

        run_logged([
            sys.executable, str(project / "report_conpot.py"),
            str(evidence_path), "--labels", str(labels),
            "--since", args.since, "--until", args.until,
            "--output", str(section / "report"),
        ], section / "report-builder.log")

    save_manifest()
    print("Combined report directory:", folder, flush=True)

    for name, action in (("ssh_http", mixed), ("modbus", modbus)):
        section = manifest["sections"][name]
        if (name == "ssh_http" and args.skip_mixed) or (name == "modbus" and args.skip_conpot):
            section.update(status="not_selected", reason="Not selected in reporting configuration.")
            save_manifest()
            continue
        section.update(status="running", started_at=now())
        save_manifest()
        try:
            action()
            section["status"] = "completed"
        except Exception as exc:
            section["status"] = "failed"
            section["error"] = str(exc)
        section["finished_at"] = now()
        save_manifest()
        print(name + ": " + section["status"], flush=True)

    failed = any(
        item["status"] not in ("completed", "not_selected")
        for item in manifest["sections"].values()
    )
    manifest["status"] = "failed" if failed else "completed"
    manifest["finished_at"] = now()

    sections = [
        ("MIXED-SERVICE CONNECTION REPORT", "ssh_http", folder / "ssh-http/report.txt"),
        ("MODBUS LOGGED-START REPORT", "modbus", folder / "modbus/report/report.txt"),
    ]
    lines = [
        "COMBINED HONEYPOT REPORT",
        "Status: " + manifest["status"],
        "Metrics are presented separately; no combined connection total.",
        "",
    ]
    try:
        for title, key, path in sections:
            lines.append(title)
            if manifest["sections"][key]["status"] == "completed":
                lines.append(path.read_text())
            elif manifest["sections"][key]["status"] == "not_selected":
                lines.append("NOT SELECTED: excluded by configuration; no zero count inferred.")
            else:
                lines.append("FAILED: " + manifest["sections"][key]["error"])
            lines.append("")
        (folder / "report.txt").write_text("\n".join(lines))
    except OSError as exc:
        failed = True
        manifest["status"] = "failed"
        manifest["summary_error"] = str(exc)

    save_manifest()
    print("Final status:", manifest["status"])
    print("Manifest:", folder / "collection-manifest.json")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

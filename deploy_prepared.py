import argparse
import fcntl
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def contained(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Prepared path escapes its directory.")
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("prepared", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    os.umask(0o077)
    project = Path(__file__).resolve().parent
    prepared = args.prepared.resolve()
    folder = None
    outcome = None

    with (project / ".mixed-pipeline.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.exit(1, "Another pipeline operation is active.\n")

        try:
            preparation = json.loads(
                (prepared / "preparation-manifest.json").read_text()
            )
            if preparation.get("status") != "prepared":
                raise ValueError("Preparation is not complete.")

            folder = args.output.expanduser().resolve()
            folder.mkdir(parents=True, exist_ok=False)
            outcome = {
                "schema_version": 1,
                "status": "preflight",
                "started_at": now(),
                "prepared_directory": str(prepared),
                "releases": [],
                "limitations": [
                    "Release upgrades are sequential, not atomic.",
                    "No automatic cross-release rollback is performed.",
                    "State checks do not replace backups.",
                    "Database row counts and log sizes do not prove complete content preservation.",
                ],
            }

            def save():
                write_json(folder / "deployment-result.json", outcome)

            def preflight(label):
                destination = folder / label
                subprocess.run([
                    sys.executable, str(project / "preflight_run.py"),
                    str(prepared), "--output", str(destination),
                    "--lock-fd", str(lock.fileno()),
                ], pass_fds=(lock.fileno(),), check=True, timeout=600)
                report = json.loads(
                    (destination / "preflight.json").read_text()
                )
                if report["status"] != "passed":
                    raise ValueError("Preflight did not pass.")
                return {
                    (item["namespace"], item["release"]): item
                    for item in report["releases"]
                }

            def observe_service(name, namespace, phase, destination):
                started = now()
                result = subprocess.check_output([
                    "kubectl", "get", "service", name,
                    "-n", namespace, "-o", "json",
                ], text=True, timeout=60)
                write_json(destination, {
                    "release": name,
                    "namespace": namespace,
                    "phase": phase,
                    "observation_started_at": started,
                    "observation_finished_at": now(),
                    "service": json.loads(result),
                })

            save()
            baseline = preflight("preflight-before")
            outcome["status"] = "deploying"
            save()

            for item in preparation["releases"]:
                name = item["release"]
                namespace = item["namespace"]
                key = (namespace, name)
                chart = contained(prepared, item["chart"])
                values = [contained(prepared, value) for value in item["values"]]

                release_dir = folder / name
                release_dir.mkdir()
                record = {
                    "release": name,
                    "namespace": namespace,
                    "status": "starting",
                    "started_at": now(),
                    "previous_revision": baseline[key]["helm_revision"],
                }
                outcome["releases"].append(record)
                save()

                # Preserve the installed manifest for review or recovery.
                with (release_dir / "helm-manifest-before.yaml").open("w") as output:
                    subprocess.run([
                        "helm", "get", "manifest", name, "-n", namespace,
                    ], stdout=output, check=True, timeout=60)

                observe_service(
                    name, namespace, "before_upgrade",
                    release_dir / "service-observation-before.json",
                )

                command = [
                    "helm", "upgrade", name, str(chart), "-n", namespace,
                ]
                for value in values:
                    command.extend(["-f", str(value)])
                command.extend(["--wait", "--timeout", "5m"])

                record["status"] = "upgrading"
                save()
                print("Upgrading:", namespace + "/" + name, flush=True)

                with (release_dir / "helm-upgrade.log").open("w") as output:
                    subprocess.run(
                        command, stdout=output, stderr=subprocess.STDOUT,
                        check=True, timeout=360,
                    )

                record["status"] = "verifying"
                save()

                # Reuse the same checks while retaining the pipeline lock.
                verified = preflight("checks-after-" + name)
                before = baseline[key]["checks"]
                after = verified[key]["checks"]

                if "cowrie" in before:
                    if (
                        before["cowrie"]["ed25519_fingerprint"]
                        != after["cowrie"]["ed25519_fingerprint"]
                    ):
                        raise ValueError("Cowrie SSH fingerprint changed.")
                if "dionaea" in before:
                    if (
                        after["dionaea"]["connection_rows"]
                        < before["dionaea"]["connection_rows"]
                    ):
                        raise ValueError("Dionaea connection-row count decreased.")
                if "conpot" in before:
                    if after["conpot"]["log_bytes"] < before["conpot"]["log_bytes"]:
                        raise ValueError("Conpot log size decreased.")

                observe_service(
                    name, namespace, "after_upgrade",
                    release_dir / "service-observation-after.json",
                )
                record.update({
                    "status": "verified",
                    "finished_at": now(),
                    "new_revision": verified[key]["helm_revision"],
                    "checks_before": before,
                    "checks_after": after,
                })
                save()
                print("PASS:", name, flush=True)

            outcome["status"] = "completed"
            outcome["finished_at"] = now()
            save()
            print("All selected releases upgraded and verified.")
            print("Deployment evidence:", folder)

        except Exception as exc:
            if outcome is not None:
                outcome["status"] = "failed"
                outcome["error"] = str(exc)
                outcome["finished_at"] = now()
                for record in outcome["releases"]:
                    if record["status"] != "verified":
                        record["status"] = "failed"
                write_json(folder / "deployment-result.json", outcome)
            parser.exit(1, f"Deployment stopped: {exc}\n")


if __name__ == "__main__":
    main()

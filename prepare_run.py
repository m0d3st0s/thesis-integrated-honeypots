import argparse
import fcntl
import hashlib
import json
import subprocess
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_directory", type=Path)
    parser.add_argument("--deployment-config", required=True, type=Path)
    parser.add_argument("--runtime-config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    project = Path(__file__).resolve().parent
    folder = None
    manifest = None

    # Share the existing pipeline lock on this controller.
    with (project / ".mixed-pipeline.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.exit(1, "Another pipeline run is active.\n")

        try:
            runtime_path = args.runtime_config.expanduser().resolve()
            runtime = json.loads(runtime_path.read_text())
            if runtime.get("schema_version") != 1:
                raise ValueError("Unsupported runtime configuration.")

            endpoint = runtime["honeychart_endpoint"]
            if not isinstance(endpoint, str) or not endpoint.startswith(
                ("http://", "https://")
            ):
                raise ValueError("Expected an HTTP(S) HoneyChart endpoint.")

            pins = Path(runtime["image_pins"]).expanduser()
            if not pins.is_absolute():
                pins = runtime_path.parent / pins
            pins = pins.resolve()
            pins_bytes = pins.read_bytes()

            state_root = Path(runtime["state_root"]).expanduser()
            if not state_root.is_absolute() or ".." in state_root.parts:
                raise ValueError("Invalid state root.")
            hostname = runtime["node_hostname"]
            if not isinstance(hostname, str) or not hostname:
                raise ValueError("Missing node hostname.")

            folder = args.output.expanduser().resolve()
            folder.mkdir(parents=True, exist_ok=False)
            write_json(folder / "runtime-config.json", runtime)
            (folder / "image-pins.yaml").write_bytes(pins_bytes)
            (folder / "deployment-config.json").write_bytes(
                args.deployment_config.read_bytes()
            )

            manifest = {
                "schema_version": 1,
                "status": "preparing",
                "started_at": now(),
                "deployment_performed": False,
                "releases": [],
                "limitations": [
                    "Validation does not prove application behavior.",
                    "Storage directories, keys, and databases require deployment preflight.",
                    "All hostPath data must exist on the selected node.",
                    "This controller lock does not coordinate other HoneyChart clients.",
                ],
            }

            def save():
                write_json(folder / "preparation-manifest.json", manifest)

            def run(command, output=None):
                print("+", " ".join(command), flush=True)
                if output is None:
                    subprocess.run(command, check=True, timeout=180)
                else:
                    with output.open("w") as stream:
                        subprocess.run(
                            command, stdout=stream, check=True, timeout=180
                        )

            save()

            # Resolve the configured hostname label to exactly one node.
            nodes = json.loads(subprocess.check_output(
                ["kubectl", "get", "nodes", "-o", "json"],
                text=True, timeout=60,
            ))
            matching = [
                item["metadata"]["name"]
                for item in nodes["items"]
                if item["metadata"].get("labels", {}).get(
                    "kubernetes.io/hostname"
                ) == hostname
            ]
            if len(matching) != 1:
                raise ValueError("Hostname label must identify exactly one node.")
            manifest["storage_node"] = matching[0]
            save()

            requests_dir = folder / "requests"
            run([
                sys.executable, str(project / "build_requests.py"),
                str(args.evidence_directory.resolve()),
                "--config", str(folder / "deployment-config.json"),
                "--output", str(requests_dir),
            ])
            requests = json.loads(
                (requests_dir / "request-manifest.json").read_text()
            )

            for item in requests["requests"]:
                name = item["release"]
                namespace = item["namespace"]
                request_path = requests_dir / item["file"]
                request = json.loads(request_path.read_text())
                selected = set(request["honeypots"]["names"])

                record = {
                    "release": name,
                    "namespace": namespace,
                    "status": "preparing",
                    "started_at": now(),
                }
                manifest["releases"].append(record)
                save()

                release_dir = folder / name
                release_dir.mkdir()
                archive = release_dir / "chart.zip"
                body = request_path.read_bytes()
                http_request = urllib.request.Request(
                    endpoint, data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(http_request, timeout=120) as response:
                    archive.write_bytes(response.read())

                with zipfile.ZipFile(archive) as zipped:
                    seen = set()
                    for member in zipped.infolist():
                        path = Path(member.filename)
                        if (
                            path.is_absolute()
                            or ".." in path.parts
                            or not path.parts
                            or path.parts[0] != name
                            or member.filename in seen
                            or (member.external_attr >> 16) & 0o170000 == 0o120000
                        ):
                            raise ValueError("Unexpected chart archive entry.")
                        seen.add(member.filename)
                    if zipped.testzip() is not None:
                        raise ValueError("Chart archive failed its integrity check.")
                    zipped.extractall(release_dir)

                chart = release_dir / name
                if selected == {"conpot"}:
                    run([
                        sys.executable, str(project / "prepare_conpot_chart.py"),
                        str(chart), "--request", str(request_path),
                    ])
                    values = [release_dir / (name + "-recipe-values.json")]
                elif selected and selected.issubset({"cowrie", "dionaea"}):
                    run([
                        sys.executable, str(project / "prepare_protocol_chart.py"),
                        str(chart), "--request", str(request_path),
                        "--state-root", str(state_root),
                        "--node-hostname", hostname,
                    ])
                    values = [
                        folder / "image-pins.yaml",
                        release_dir / (name + "-recipe-values.json"),
                    ]
                else:
                    raise ValueError("No preparation recipe for this selection.")

                # Apply node-local storage placement to either recipe.
                placement = release_dir / "placement-values.json"
                write_json(placement, {
                    "nodeSelector": {"kubernetes.io/hostname": hostname}
                })
                values.append(placement)
                value_args = [
                    argument
                    for path in values
                    for argument in ("-f", str(path))
                ]

                run(["helm", "lint", str(chart)] + value_args)
                rendered = release_dir / "rendered.yaml"
                run([
                    "helm", "template", name, str(chart),
                    "-n", namespace,
                ] + value_args, output=rendered)
                run([
                    "kubectl", "apply", "--dry-run=server",
                    "-n", namespace, "-f", str(rendered),
                ])

                record.update({
                    "status": "validated",
                    "finished_at": now(),
                    "chart": str(chart.relative_to(folder)),
                    "values": [str(path.relative_to(folder)) for path in values],
                    "rendered": str(rendered.relative_to(folder)),
                    "rendered_sha256": hashlib.sha256(
                        rendered.read_bytes()
                    ).hexdigest(),
                })
                save()

            if not manifest["releases"]:
                raise ValueError("No releases were prepared.")

            manifest["status"] = "prepared"
            manifest["finished_at"] = now()
            save()
            print("PASS: all selected charts prepared and validated.")
            print("Preparation directory:", folder)
            print("No deployment performed.")

        except Exception as exc:
            if folder is not None and manifest is not None:
                manifest["status"] = "failed"
                manifest["error"] = str(exc)
                manifest["finished_at"] = now()
                for item in manifest["releases"]:
                    if item["status"] == "preparing":
                        item["status"] = "failed"
                write_json(folder / "preparation-manifest.json", manifest)
            parser.exit(1, f"Preparation failed: {exc}\n")


if __name__ == "__main__":
    main()

import argparse
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


def main():
    parser = argparse.ArgumentParser(
        description="Discover services and prepare, install, or upgrade honeypot releases."
    )
    parser.add_argument("--scan-config", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--deployment-config", required=True, type=Path)
    parser.add_argument("--runtime-config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--mode", choices=("prepare", "install", "upgrade"),
        help="Action after discovery; defaults to prepare.",
    )
    modes.add_argument(
        "--deploy", action="store_true",
        help="Compatibility alias for --mode upgrade.",
    )
    args = parser.parse_args()
    mode = args.mode or ("upgrade" if args.deploy else "prepare")

    os.umask(0o077)
    project = Path(__file__).resolve().parent
    folder = None
    manifest = None

    try:
        inputs = {
            "scan": args.scan_config.expanduser().resolve(),
            "catalog": args.catalog.expanduser().resolve(),
            "deployment": args.deployment_config.expanduser().resolve(),
            "runtime": args.runtime_config.expanduser().resolve(),
        }
        contents = {key: path.read_bytes() for key, path in inputs.items()}

        # Resolve the image-pins path before copying the runtime configuration.
        runtime = json.loads(contents["runtime"])
        pins = Path(runtime["image_pins"]).expanduser()
        if not pins.is_absolute():
            pins = inputs["runtime"].parent / pins
        pin_contents = pins.resolve().read_bytes()

        folder = args.output.expanduser().resolve()
        folder.mkdir(parents=True, exist_ok=False)
        config_dir = folder / "config"
        config_dir.mkdir()

        for key in ("scan", "catalog", "deployment"):
            (config_dir / (key + ".json")).write_bytes(contents[key])
        (config_dir / "image-pins.yaml").write_bytes(pin_contents)
        (config_dir / "runtime-original.json").write_bytes(contents["runtime"])
        runtime["image_pins"] = "image-pins.yaml"
        write_json(config_dir / "runtime.json", runtime)

        manifest = {
            "schema_version": 1,
            "started_at": now(),
            "status": "running",
            "deployment_requested": mode != "prepare",
            "mode": mode,
            "input_sources": {key: str(path) for key, path in inputs.items()},
            "stages": [],
            "limitations": [
                "Discovery covers configured ports and responding devices only.",
                "Install mode requires absent releases and empty dedicated storage roots.",
                "Upgrade mode requires existing compatible releases or supported retained state.",
                "Release operations are sequential, not atomic.",
                "Cluster and namespace setup are prerequisites.",
                "Preparation and deployment use their own pipeline locks.",
                "Reporting is collected separately through the reporting workflow.",
            ],
        }

        def save():
            write_json(folder / "system-run.json", manifest)

        def stage(name, command):
            record = {
                "name": name,
                "status": "running",
                "started_at": now(),
                "command": command,
            }
            manifest["stages"].append(record)
            save()
            print("\nStage:", name, flush=True)
            try:
                subprocess.run(command, check=True)
            except BaseException:
                record["status"] = "failed"
                record["finished_at"] = now()
                save()
                raise
            record["status"] = "completed"
            record["finished_at"] = now()
            save()

        save()
        print("System run directory:", folder, flush=True)

        evidence = folder / "discovery"
        stage("discovery", [
            sys.executable, str(project / "scan_network.py"),
            "--config", str(config_dir / "scan.json"),
            "--catalog", str(config_dir / "catalog.json"),
            "--output", str(evidence),
        ])

        discovery = json.loads((evidence / "scan-manifest.json").read_text())
        if discovery["status"] == "no_targets":
            manifest["status"] = "no_targets"
            manifest["finished_at"] = now()
            save()
            print("No targets discovered; no deployment performed.")
            return 0
        if discovery["status"] != "completed":
            raise ValueError("Discovery did not complete.")

        prepared = folder / "prepared"
        stage("preparation", [
            sys.executable, str(project / "prepare_run.py"),
            str(evidence),
            "--deployment-config", str(config_dir / "deployment.json"),
            "--runtime-config", str(config_dir / "runtime.json"),
            "--output", str(prepared),
        ])

        if mode == "install":
            stage("installation", [
                sys.executable, str(project / "install_prepared.py"),
                str(prepared),
                "--output", str(folder / "installation"),
                "--install",
            ])
            manifest["status"] = "installed"
        elif mode == "upgrade":
            stage("deployment", [
                sys.executable, str(project / "deploy_prepared.py"),
                str(prepared),
                "--output", str(folder / "deployment"),
            ])
            manifest["status"] = "deployed"
        else:
            manifest["status"] = "prepared"

        manifest["finished_at"] = now()
        save()
        print("\nSystem run status:", manifest["status"])
        print("Evidence:", folder)
        if mode == "prepare":
            print("No deployment performed.")
        return 0

    except (Exception, KeyboardInterrupt) as exc:
        if folder is not None and manifest is not None:
            manifest["status"] = "failed"
            manifest["error"] = str(exc) or type(exc).__name__
            manifest["finished_at"] = now()
            write_json(folder / "system-run.json", manifest)
        print("System run stopped:", str(exc) or type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

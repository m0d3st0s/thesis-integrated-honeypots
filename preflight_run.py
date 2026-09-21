import argparse
from inspect_retained_dionaea import inspect_retained_dionaea
import fcntl
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def command(argv):
    return subprocess.check_output(argv, text=True, timeout=120)


def get_json(argv):
    return json.loads(command(argv))


def inside(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Prepared path escapes its directory.")
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("prepared", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--lock-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--allow-retained-dionaea", action="store_true")
    args = parser.parse_args()

    project = Path(__file__).resolve().parent
    folder = None
    report = None

    lock_path = project / ".mixed-pipeline.lock"
    if args.lock_fd is None:
        lock_stream = lock_path.open("a")
    else:
        inherited = os.fstat(args.lock_fd)
        expected = lock_path.stat()
        if (inherited.st_dev, inherited.st_ino) != (
            expected.st_dev, expected.st_ino
        ):
            parser.exit(1, "Inherited descriptor is not the pipeline lock.\n")
        lock_stream = os.fdopen(os.dup(args.lock_fd), "a")

    with lock_stream as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.exit(1, "Another pipeline operation is active.\n")

        try:
            prepared = args.prepared.resolve()
            manifest = json.loads(
                (prepared / "preparation-manifest.json").read_text()
            )
            runtime = json.loads((prepared / "runtime-config.json").read_text())
            if manifest.get("status") != "prepared" or not manifest["releases"]:
                raise ValueError("Expected a completed preparation run.")

            node = manifest["storage_node"]
            node_data = get_json(["kubectl", "get", "node", node, "-o", "json"])
            if node_data["metadata"]["labels"].get(
                "kubernetes.io/hostname"
            ) != runtime["node_hostname"]:
                raise ValueError("Storage-node hostname label changed.")
            if node_data["spec"].get("unschedulable"):
                raise ValueError("Storage node is marked unschedulable.")
            if not any(
                item["type"] == "Ready" and item["status"] == "True"
                for item in node_data["status"]["conditions"]
            ):
                raise ValueError("Storage node is not Ready.")

            folder = args.output.expanduser().resolve()
            folder.mkdir(parents=True, exist_ok=False)
            report = {
                "schema_version": 1,
                "status": "checking",
                "started_at": now(),
                "prepared_directory": str(prepared),
                "storage_node": node,
                "releases": [],
                "note": (
                    "Point-in-time preflight. Deployment must recheck under "
                    "the pipeline lock before making changes."
                ),
            }
            write_json(folder / "preflight.json", report)
            write_json(folder / "node.json", node_data)

            seen = set()
            for item in manifest["releases"]:
                name = item["release"]
                namespace = item["namespace"]
                if item["status"] != "validated":
                    raise ValueError("A release was not validated.")
                if (namespace, name) in seen:
                    raise ValueError("Duplicate release.")
                seen.add((namespace, name))

                print("Checking:", namespace + "/" + name, flush=True)
                result = {
                    "release": name,
                    "namespace": namespace,
                    "status": "checking",
                }
                report["releases"].append(result)
                write_json(folder / "preflight.json", report)

                chart = inside(prepared, item["chart"])
                values = [inside(prepared, path) for path in item["values"]]
                value_args = [
                    argument for path in values
                    for argument in ("-f", str(path))
                ]
                rendered = subprocess.check_output([
                    "helm", "template", name, str(chart), "-n", namespace,
                ] + value_args, timeout=120)
                if hashlib.sha256(rendered).hexdigest() != item["rendered_sha256"]:
                    raise ValueError("Prepared rendering changed for " + name)

                release_dir = folder / name
                release_dir.mkdir()
                rendered_path = release_dir / "rendered-rechecked.yaml"
                rendered_path.write_bytes(rendered)
                subprocess.run([
                    "kubectl", "apply", "--dry-run=server",
                    "-n", namespace, "-f", str(rendered_path),
                ], check=True, timeout=120)

                helm = get_json([
                    "helm", "status", name, "-n", namespace, "-o", "json"
                ])
                if helm["info"]["status"] != "deployed":
                    raise ValueError("Existing Helm release is not deployed.")

                deployment = get_json([
                    "kubectl", "get", "deployment", name,
                    "-n", namespace, "-o", "json",
                ])
                service = get_json([
                    "kubectl", "get", "service", name,
                    "-n", namespace, "-o", "json",
                ])
                pods = get_json([
                    "kubectl", "get", "pods", "-n", namespace,
                    "-l", "app.kubernetes.io/instance=" + name, "-o", "json",
                ])
                for label, data in (
                    ("helm-status", helm), ("deployment", deployment),
                    ("service", service), ("pods", pods),
                ):
                    write_json(release_dir / (label + "-before.json"), data)

                active = [
                    pod for pod in pods["items"]
                    if not pod["metadata"].get("deletionTimestamp")
                ]
                if len(active) != 1:
                    raise ValueError("Expected one active Pod for " + name)
                pod = active[0]
                if pod["spec"].get("nodeName") != node:
                    raise ValueError("Existing Pod is on another storage node.")
                if not any(
                    condition["type"] == "Ready"
                    and condition["status"] == "True"
                    for condition in pod["status"].get("conditions", [])
                ):
                    raise ValueError("Existing Pod is not Ready.")

                request = json.loads(
                    (prepared / "requests" / (name + ".request.json")).read_text()
                )
                containers = {
                    container["name"]: container
                    for container in pod["spec"]["containers"]
                }
                volumes = {
                    volume["name"]: volume
                    for volume in pod["spec"].get("volumes", [])
                }
                state_root = Path(runtime["state_root"]).expanduser()
                state_mounts = {
                    "cowrie": "/cowrie/cowrie-git/var/lib/cowrie",
                    "dionaea": "/opt/dionaea/var/lib/dionaea",
                }
                log_mounts = {
                    "cowrie": "/cowrie/cowrie-git/var/log/cowrie",
                    "dionaea": "/json-logs",
                    "conpot": "/conpot-json-logs",
                }
                checks = {}

                for hp in request["honeypots"]["names"]:
                    if hp not in containers:
                        if hp == "dionaea" and args.allow_retained_dionaea:
                            checks[hp] = inspect_retained_dionaea(
                                namespace,
                                runtime["node_hostname"],
                                state_root / name / hp,
                                request["honeypots"][hp]["volumes"][0],
                                release_dir / "retained-dionaea",
                            )
                            continue
                        raise ValueError(
                            "Selected container is not currently running: " + hp
                        )
                    container = containers[hp]
                    mounts = {
                        mount["mountPath"]: mount
                        for mount in container.get("volumeMounts", [])
                    }
                    expected = {
                        log_mounts[hp]: request["honeypots"][hp]["volumes"][0]
                    }
                    if hp in state_mounts:
                        expected[state_mounts[hp]] = str(state_root / name / hp)
                    for mount_path, host_path in expected.items():
                        mount = mounts.get(mount_path)
                        if (
                            mount is None
                            or mount.get("subPath")
                            or mount.get("subPathExpr")
                            or mount.get("readOnly", False)
                        ):
                            raise ValueError("Unexpected mount: " + mount_path)
                        volume = volumes[mount["name"]]
                        if volume.get("hostPath", {}).get("path") != host_path:
                            raise ValueError("Persistent host path differs from plan.")

                    if hp == "cowrie":
                        python = "/cowrie/cowrie-env/bin/python3"
                        code = """
import base64, hashlib, json, os
from pathlib import Path
root = Path('/cowrie/cowrie-git/var/lib/cowrie')
for name in ('rsa', 'ecdsa', 'ed25519'):
    for suffix in ('', '.pub'):
        path = root / ('ssh_host_' + name + '_key' + suffix)
        if not path.is_file() or path.stat().st_size == 0:
            raise SystemExit('Missing Cowrie key: ' + path.name)
parts = (root / 'ssh_host_ed25519_key.pub').read_text().split()
digest = hashlib.sha256(base64.b64decode(parts[1], validate=True)).digest()
fingerprint = 'SHA256:' + base64.b64encode(digest).decode().rstrip('=')
if not os.access(str(root), os.W_OK):
    raise SystemExit('Cowrie state directory is not writable.')
print(json.dumps({'ed25519_fingerprint': fingerprint}))
"""
                    elif hp == "dionaea":
                        python = "python3"
                        code = """
import json, sqlite3
db = sqlite3.connect(
    'file:/opt/dionaea/var/lib/dionaea/dionaea.sqlite?mode=ro', uri=True)
try:
    if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
        raise SystemExit('Dionaea database integrity check failed.')
    count = db.execute('SELECT COUNT(*) FROM connections').fetchone()[0]
    print(json.dumps({'database_integrity': 'ok', 'connection_rows': count}))
finally:
    db.close()
"""
                    else:
                        python = "python3"
                        code = """
import json, os
from pathlib import Path
folder = Path('/conpot-json-logs')
log = folder / 'conpot.json'
if not folder.is_dir() or not os.access(str(folder), os.W_OK):
    raise SystemExit('Conpot log directory is not writable.')
if not log.is_file() or not os.access(str(log), os.W_OK):
    raise SystemExit('Existing Conpot log is missing or not writable.')
print(json.dumps({'log_writable': True, 'log_bytes': log.stat().st_size}))
"""
                    checks[hp] = get_json([
                        "kubectl", "exec", "-n", namespace,
                        pod["metadata"]["name"], "-c", hp,
                        "--", python, "-c", code,
                    ])

                result.update({
                    "status": "passed",
                    "helm_revision": helm["version"],
                    "deployment_resource_version": deployment["metadata"]["resourceVersion"],
                    "service_resource_version": service["metadata"]["resourceVersion"],
                    "pod_uid": pod["metadata"]["uid"],
                    "checks": checks,
                })
                write_json(folder / "preflight.json", report)
                print("PASS:", name, flush=True)

            report["status"] = "passed"
            report["finished_at"] = now()
            write_json(folder / "preflight.json", report)
            print("All release preflight checks passed.")
            print("Evidence:", folder)
            print("No deployment performed.")

        except Exception as exc:
            if folder is not None and report is not None:
                report["status"] = "failed"
                report["error"] = str(exc)
                report["finished_at"] = now()
                write_json(folder / "preflight.json", report)
            parser.exit(1, f"Preflight failed: {exc}\n")


if __name__ == "__main__":
    main()

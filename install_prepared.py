#!/usr/bin/env python3
"""First installation of the verified, node-local honeypot recipes.

Requires an existing Kubernetes namespace/node and prepared HoneyChart output.
Default: validate only. --install: initialize empty roots and install releases.
Run from the integrated-system repository alongside preflight_run.py.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


# Image layout and initialization recipes verified in the first-install experiment.
RECIPES = {
    "cowrie": {
        "digest": "c2367443a0a0b983b5238314a03808f151523789989c7f07f021bc1971d6565e",
        "python": "/cowrie/cowrie-env/bin/python3",
        "state": "/cowrie/cowrie-git/var/lib/cowrie",
        "log": "/cowrie/cowrie-git/var/log/cowrie",
    },
    "dionaea": {
        "digest": "55150e2a9ef56e1b304129195affc0dc335ed35868dfde6de0ff1f2358d00515",
        "python": "python3",
        "state": "/opt/dionaea/var/lib/dionaea",
        "log": "/json-logs",
    },
    "conpot": {
        "digest": "9837ce01a254bd5dc3c92ea85741135a04f03aab27c0642b0ea728ecd4a128ca",
        "python": "python3",
        "log": "/conpot-json-logs",
    },
}

INIT_CODE = r'''
import json, os, shutil, sys
from pathlib import Path
action, release, hp = sys.argv[1:4]
state, logs = Path('/fresh-state'), Path('/fresh-logs')
if action == 'check':
    for root in (state, logs):
        if any(root.iterdir()):
            raise SystemExit('Storage root is not empty: ' + str(root))
    print('PASS: both storage roots empty', flush=True)
    sys.exit(0)

def directory(path):
    path.mkdir(parents=True, exist_ok=False)
    os.chown(str(path), 1000, 1000)
    os.chmod(str(path), 0o750)

target = state / release / hp
if hp == 'dionaea':
    template = Path('/opt/dionaea/template/lib/dionaea')
    if not template.is_dir():
        raise SystemExit('Dionaea template is missing.')
    for path in template.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise SystemExit('Unexpected template entry: ' + str(path))
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(str(template), str(target))
    for path in [target] + list(target.rglob('*')):
        os.chown(str(path), 1000, 1000)
    os.chmod(str(target), 0o750)
elif hp == 'cowrie':
    directory(target)
    for name in ('downloads', 'snapshots', 'tty'):
        directory(target / name)
directory(logs / release / hp)
print('Initialized: ' + release + ' ' + hp, flush=True)
'''


def now():
    return datetime.now(timezone.utc).isoformat()


def save(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    temporary.replace(path)


def run(command, **kwargs):
    return subprocess.run(command, check=True, timeout=kwargs.pop("timeout", 120),
                          **kwargs)


def get_json(command):
    return json.loads(run(command, capture_output=True).stdout)


def inside(root, value):
    path = (root / value).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Prepared path escapes its directory.")
    return path


def storage_root(value):
    path = Path(value).expanduser()
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 4:
        raise ValueError("Use a dedicated absolute storage root: " + str(path))
    return path


def absent(namespace, name, objects):
    releases = get_json(["helm", "list", "-n", namespace, "--all", "--filter",
                         "^" + re.escape(name) + "$", "-o", "json"])
    if releases:
        raise ValueError("Helm release already exists: " + name)
    for obj in objects:
        found = run(["kubectl", "get", obj["kind"], obj["metadata"]["name"],
                     "-n", namespace, "--ignore-not-found", "-o", "name"],
                    capture_output=True).stdout.strip()
        if found:
            raise ValueError("Resource already exists: " + found.decode())


def render(prepared, item):
    command = ["helm", "template", item["release"],
               str(inside(prepared, item["chart"])), "-n", item["namespace"]]
    for value in item["values"]:
        command += ["-f", str(inside(prepared, value))]
    raw = run(command, capture_output=True).stdout
    if hashlib.sha256(raw).hexdigest() != item["rendered_sha256"]:
        raise ValueError("Prepared rendering changed: " + item["release"])
    output = run(["kubectl", "create", "--dry-run=client",
                  "-n", item["namespace"], "-f", "-", "-o", "json"],
                 input=raw, capture_output=True).stdout.decode("utf-8")
    decoder = json.JSONDecoder()
    objects = []
    remaining = output.lstrip()
    while remaining:
        parsed, end = decoder.raw_decode(remaining)
        if not isinstance(parsed, dict):
            raise ValueError("Expected a Kubernetes JSON object.")
        if parsed.get("kind") == "List":
            objects.extend(parsed["items"])
        else:
            objects.append(parsed)
        remaining = remaining[end:].lstrip()
    if not objects:
        raise ValueError("No Kubernetes resources were rendered.")
    return raw, objects


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prepared", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--install", action="store_true",
                        help="Create storage and install; default only validates.")
    args = parser.parse_args()
    os.umask(0o077)
    project = Path(__file__).resolve().parent
    prepared = args.prepared.expanduser().resolve()
    output = args.output.expanduser().resolve()
    report = None
    with (project / ".mixed-pipeline.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            output.mkdir(parents=True, exist_ok=False)
            report = {"schema_version": 1, "status": "validating", "started_at": now(),
                      "prepared_directory": str(prepared), "install_requested": args.install,
                      "releases": [], "limitations": [
                          "Requires an existing cluster, namespace and configured storage node.",
                          "Initialization requires empty dedicated node-local storage roots.",
                          "DirectoryOrCreate may leave empty roots after a failed initialization.",
                          "Installation is sequential; failures retain state and installed releases.",
                          "This command does not configure or verify network isolation.",
                          "Only the explicitly verified image digests are supported."]}
            save(output / "installation-result.json", report)
            manifest = json.loads((prepared / "preparation-manifest.json").read_text())
            runtime = json.loads((prepared / "runtime-config.json").read_text())
            config = json.loads((prepared / "deployment-config.json").read_text())
            if manifest.get("status") != "prepared" or not manifest.get("releases"):
                raise ValueError("Expected a completed preparation.")
            namespace = config["namespace"]
            get_json(["kubectl", "get", "namespace", namespace, "-o", "json"])
            node = get_json(["kubectl", "get", "node", manifest["storage_node"], "-o", "json"])
            if (node["metadata"]["labels"].get("kubernetes.io/hostname") != runtime["node_hostname"]
                    or node["spec"].get("unschedulable") or not any(
                        c["type"] == "Ready" and c["status"] == "True"
                        for c in node["status"].get("conditions", []))):
                raise ValueError("Configured storage node is not available.")
            state, logs = storage_root(runtime["state_root"]), storage_root(config["log_root"])
            if state == logs or state in logs.parents or logs in state.parents:
                raise ValueError("State and log roots must be separate.")
            entries, checked, seen = [], [], set()
            for item in manifest["releases"]:
                name = item["release"]
                if (not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,18}[a-z0-9]", name)
                        or name in seen or item["namespace"] != namespace
                        or item["status"] != "validated"):
                    raise ValueError("Invalid prepared release.")
                seen.add(name)
                raw, objects = render(prepared, item)
                for obj in objects:
                    if (obj["kind"] not in {"Deployment", "Service", "ServiceAccount", "ConfigMap"}
                            or obj["metadata"].get("namespace", namespace) != namespace
                            or obj["metadata"].get("annotations", {}).get("helm.sh/hook")):
                        raise ValueError("Unsupported resource or Helm hook.")
                deployments = [o for o in objects if o["kind"] == "Deployment"]
                if len(deployments) != 1 or deployments[0]["metadata"]["name"] != name:
                    raise ValueError("Expected one release-named Deployment.")
                spec = deployments[0]["spec"]["template"]["spec"]
                if spec.get("nodeSelector", {}).get("kubernetes.io/hostname") != runtime["node_hostname"]:
                    raise ValueError("Chart storage-node placement differs from configuration.")
                volumes = {v["name"]: v for v in spec.get("volumes", [])}
                request = json.loads((prepared / "requests" / (name + ".request.json")).read_text())
                if request["name"] != name:
                    raise ValueError("Request release differs from manifest.")
                containers = spec["containers"]
                if sorted(c["name"] for c in containers) != sorted(request["honeypots"]["names"]):
                    raise ValueError("Request and chart containers differ.")
                for container in containers:
                    hp = container["name"]
                    recipe = RECIPES[hp]
                    image = container["image"]
                    if image not in {"ghcr.io/parasecurity/" + hp + suffix + "@sha256:" + recipe["digest"]
                                     for suffix in ("", ":latest")}:
                        raise ValueError("Unverified initialization image: " + image)
                    expected = {recipe["log"]: logs / name / hp}
                    if "state" in recipe:
                        expected[recipe["state"]] = state / name / hp
                    if request["honeypots"][hp]["volumes"] != [str(logs / name / hp)]:
                        raise ValueError("Request log path differs from configured root.")
                    mounts = {m["mountPath"]: m for m in container.get("volumeMounts", [])}
                    for target, host in expected.items():
                        mount = mounts[target]
                        if (mount.get("readOnly") or mount.get("subPath") or mount.get("subPathExpr")
                                or volumes[mount["name"]].get("hostPath") != {"path": str(host), "type": "Directory"}):
                            raise ValueError("Unexpected persistent mount: " + target)
                    entries.append({"release": name, "honeypot": hp, "image": image})
                absent(namespace, name, objects)
                run(["kubectl", "apply", "--dry-run=server", "-n", namespace, "-f", "-"], input=raw)
                (output / (name + "-rendered.yaml")).write_bytes(raw)
                checked.append((item, objects))
            report.update({"status": "validated", "state_root": str(state), "log_root": str(logs),
                           "initialization_entries": entries})
            save(output / "installation-result.json", report)
            if not args.install:
                print("PASS: first-install chart and release checks passed.")
                print("Storage emptiness will be checked on the node during --install.")
                print("No storage or releases created. Evidence:", output)
                return
            if not (project / "preflight_run.py").is_file():
                raise ValueError("Place this script beside preflight_run.py.")
            podname = "initialize-" + uuid.uuid4().hex[:12]
            def container(name, entry, action):
                return {"name": name, "image": entry["image"],
                        "command": [RECIPES[entry["honeypot"]]["python"], "-c", INIT_CODE,
                                    action, entry["release"], entry["honeypot"]],
                        "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False},
                        "volumeMounts": [{"name": "state", "mountPath": "/fresh-state"},
                                         {"name": "logs", "mountPath": "/fresh-logs"}]}
            init = [container("check-empty", entries[0], "check")]
            init += [container("initialize-" + str(i), e, "initialize") for i, e in enumerate(entries)]
            pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": podname, "namespace": namespace},
                   "spec": {"restartPolicy": "Never", "activeDeadlineSeconds": 180,
                            "automountServiceAccountToken": False,
                            "nodeSelector": {"kubernetes.io/hostname": runtime["node_hostname"]},
                            "initContainers": init,
                            "containers": [{"name": "complete", "image": entries[0]["image"],
                                            "command": [RECIPES[entries[0]["honeypot"]]["python"],
                                                        "-c", "print('Initialization completed.')"]}],
                            "volumes": [{"name": key, "hostPath": {"path": str(path), "type": "DirectoryOrCreate"}}
                                        for key, path in (("state", state), ("logs", logs))]}}
            save(output / "initialization-pod.json", pod)
            report["status"] = "initializing"
            save(output / "installation-result.json", report)
            run(["kubectl", "create", "-f", "-"], input=json.dumps(pod).encode())
            try:
                deadline = time.monotonic() + 210
                while True:
                    status = get_json(["kubectl", "get", "pod", podname, "-n", namespace, "-o", "json"])
                    save(output / "initialization-pod-result.json", status)
                    phase = status["status"].get("phase")
                    if phase in {"Succeeded", "Failed"}:
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Initialization Pod timed out.")
                    time.sleep(2)
                if phase != "Succeeded":
                    raise ValueError("Storage initialization failed; inspect Pod results and logs.")
            finally:
                try:
                    for c in init + pod["spec"]["containers"]:
                        result = subprocess.run(["kubectl", "logs", podname, "-n", namespace, "-c", c["name"]],
                                                capture_output=True, timeout=30)
                        (output / (c["name"] + ".log")).write_bytes(result.stdout + result.stderr)
                finally:
                    run(["kubectl", "delete", "pod", podname, "-n", namespace,
                         "--ignore-not-found", "--wait=true", "--timeout=30s"])
            for item, objects in checked:
                name = item["release"]
                absent(namespace, name, objects)
                render(prepared, item)  # Recheck prepared content immediately before installation.
                record = {"release": name, "namespace": namespace, "status": "installing", "started_at": now()}
                report["releases"].append(record)
                report["status"] = "installing"
                save(output / "installation-result.json", report)
                command = ["helm", "install", name, str(inside(prepared, item["chart"])), "-n", namespace]
                for value in item["values"]:
                    command += ["-f", str(inside(prepared, value))]
                command += ["--wait", "--timeout", "5m"]
                print("Installing:", name, flush=True)
                with (output / (name + "-install.log")).open("wb") as log:
                    run(command, stdout=log, stderr=subprocess.STDOUT, timeout=360)
                record.update({"status": "installed", "finished_at": now()})
                save(output / "installation-result.json", report)
            run([sys.executable, str(project / "preflight_run.py"), str(prepared),
                 "--output", str(output / "runtime-checks"), "--lock-fd", str(lock.fileno())],
                pass_fds=(lock.fileno(),), timeout=600)
            checks = json.loads((output / "runtime-checks/preflight.json").read_text())
            if checks["status"] != "passed":
                raise ValueError("Post-install verification failed.")
            report.update({"status": "completed", "finished_at": now(), "runtime_checks": checks})
            save(output / "installation-result.json", report)
            print("PASS: first installation and runtime checks completed. Evidence:", output)
        except Exception as exc:
            if report is not None:
                report.update({"status": "failed", "error": str(exc), "finished_at": now()})
                save(output / "installation-result.json", report)
            parser.exit(1, "First installation stopped: " + str(exc) + "\n")


if __name__ == "__main__":
    main()

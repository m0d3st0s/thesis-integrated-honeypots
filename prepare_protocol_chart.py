import argparse
import json
import re
from pathlib import Path
from protocol_support import requested_listeners
from smb_repair_chart import repair_assets


def prepare(chart, request_path, state_root, node_hostname):
    chart = chart.resolve()
    request = json.loads(request_path.read_text())
    release = request["name"]

    if (
        release != chart.name
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,18}[a-z0-9]", release)
    ):
        raise ValueError("Invalid or mismatched release name.")
    if request["service"]["type"] != "NodePort":
        raise ValueError("This recipe currently requires NodePort.")
    if not node_hostname or len(node_hostname) > 63:
        raise ValueError("A valid node hostname label is required.")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", node_hostname):
        raise ValueError("Invalid node hostname label.")

    state_root = state_root.expanduser()
    if not state_root.is_absolute() or ".." in state_root.parts:
        raise ValueError("State root must be an absolute path without '..'.")

    selected = request["honeypots"]["names"]
    if (
        not selected
        or len(set(selected)) != len(selected)
        or not set(selected).issubset({"cowrie", "dionaea"})
    ):
        raise ValueError("Expected Cowrie, Dionaea, or both.")

    listeners = requested_listeners(request)
    smb_selected = any(service == "smb" for service, _, _ in listeners.get("dionaea", []))
    repair_init, repair_volumes, repair_mount, repair_outputs = (
        repair_assets(chart) if smb_selected else ("", "", "", {})
    )
    recipes = {
        "cowrie": {
            "mount_key": "cowriemountPath",
            "host_key": "cowriehostPath",
            "log_volume": "cowrie-data",
            "log_mount": "/cowrie/cowrie-git/var/log/cowrie",
            "state_mount": "/cowrie/cowrie-git/var/lib/cowrie",
        },
        "dionaea": {
            "mount_key": "dionaeamountPath",
            "host_key": "dionaeahostPath",
            "log_volume": "dioanea-data",
            "log_mount": "/json-logs",
            "state_mount": "/opt/dionaea/var/lib/dionaea",
        },
    }

    template = chart / "templates/deployment.yaml"
    original = template.read_text()
    detected = set(re.findall(
        r"\.Values\.honeypots\.([a-z0-9]+)\.image\.repository", original
    ))
    if detected != set(selected):
        raise ValueError("Chart containers do not match the request.")

    values = {
        "replicaCount": 1,
        "autoscaling": {"enabled": False},
        "serviceAccount": {"automount": False},
        "service": {"type": "NodePort", "extTrafficPolicy": "Local"},
        "nodeSelector": {"kubernetes.io/hostname": node_hostname},
        "volumes": {},
        "honeypots": {},
    }
    changes = [
        (
            'spec:\n  {{- if not .Values.autoscaling.enabled }}',
            'spec:\n  strategy:\n    type: Recreate\n'
            '    rollingUpdate: null\n'
            '  {{- if not .Values.autoscaling.enabled }}',
        ),
        (
            "      serviceAccountName:",
            repair_init + "      automountServiceAccountToken: false\n"
            "      serviceAccountName:",
        ),
    ]
    volume_block = "      volumes:\n" + repair_volumes

    for name in sorted(selected):
        recipe = recipes[name]
        item = request["honeypots"][name]
        if len(item["volumes"]) != 1:
            raise ValueError("Unsupported service configuration for " + name)
        log_path = Path(item["volumes"][0])
        if not log_path.is_absolute() or ".." in log_path.parts:
            raise ValueError("Invalid host log path.")

        old_mount = (
            "            - mountPath: {{ .Values.volumes."
            + recipe["mount_key"] + " }}\n"
            "              name: " + recipe["log_volume"]
        )
        changes.append((
            old_mount,
            old_mount + "\n"
            "            - mountPath: " + recipe["state_mount"] + "\n"
            "              name: " + name + "-state"
            + (repair_mount if name == "dionaea" else ""),
        ))

        old_log_path = (
            "            path: {{ .Values.volumes."
            + recipe["host_key"] + " }}"
        )
        changes.append((
            old_log_path,
            "            path: {{ .Values.volumes."
            + recipe["host_key"] + " | quote }}\n"
            "            type: Directory",
        ))

        state_path = state_root / release / name
        volume_block += (
            "        - name: " + name + "-state\n"
            "          hostPath:\n"
            "            path: " + json.dumps(str(state_path)) + "\n"
            "            type: Directory\n"
        )
        values["volumes"][recipe["mount_key"]] = recipe["log_mount"]
        values["volumes"][recipe["host_key"]] = str(log_path)
        ports = {}
        for service, port, listener in listeners[name]:
            ports.update({
                "name" + service: service,
                "protocol" + service: "TCP",
                "port" + service: port,
                "containerPort" + service: listener,
            })
        values["honeypots"][name] = {"ports": ports}

    changes.append(("      volumes:\n", volume_block))
    updated = original
    for old, new in changes:
        if updated.count(old) != 1:
            raise ValueError("Unexpected template near: " + repr(old))
        updated = updated.replace(old, new, 1)

    backup = chart.parent / (release + "-deployment-before-recipe.yaml")
    values_path = chart.parent / (release + "-recipe-values.json")
    test = chart / "templates/tests/test-connection.yaml"
    saved_test = chart.parent / (release + "-unused-http-test.yaml")
    destinations = [backup, values_path] + list(repair_outputs)
    if test.exists():
        destinations.append(saved_test)
    if any(path.exists() for path in destinations):
        raise ValueError("Preparation outputs exist; use a fresh chart.")

    backup.write_text(original)
    values_path.write_text(json.dumps(values, indent=2) + "\n")
    for path, data in repair_outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    template.write_text(updated)
    if test.exists():
        test.rename(saved_test)

    print("Prepared:", chart)
    print("Values:", values_path)
    print("Storage node hostname:", node_hostname)
    print("Also supply the pinned-image values file to Helm.")
    print("Host directories and existing state were not modified.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("chart", type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--node-hostname", required=True)
    args = parser.parse_args()
    try:
        prepare(
            args.chart, args.request, args.state_root, args.node_hostname
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()

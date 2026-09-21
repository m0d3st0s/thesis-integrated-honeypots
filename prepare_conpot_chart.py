import argparse
import hashlib
import json
from pathlib import Path


def prepare(chart, request_path, assets):
    chart = chart.resolve()
    request = json.loads(request_path.read_text())
    manifest = json.loads((assets / "manifest.json").read_text())

    if manifest.get("recipe") != "conpot-modbus-v1":
        raise ValueError("Unsupported Conpot recipe.")
    if request["name"] != chart.name:
        raise ValueError("Request name and chart directory do not match.")
    if request["honeypots"]["names"] != ["conpot"]:
        raise ValueError("This recipe requires a Conpot-only chart.")
    if request["service"]["type"] != "NodePort":
        raise ValueError("This recipe currently requires NodePort.")

    conpot = request["honeypots"]["conpot"]
    if (
        len(conpot["services"]) != 1
        or set(conpot["services"][0]) != {"modbus"}
        or conpot["containerports"] != [5020]
        or conpot["protocols"] != ["TCP"]
        or len(conpot["volumes"]) != 1
    ):
        raise ValueError("Expected exactly one Modbus TCP service on listener 5020.")

    service_port = conpot["services"][0]["modbus"]
    if type(service_port) is not int or not 1 <= service_port <= 65535:
        raise ValueError("Invalid Service port.")

    log_path = Path(conpot["volumes"][0])
    if not log_path.is_absolute() or ".." in log_path.parts:
        raise ValueError("Expected an absolute host log path without '..'.")

    names = (
        "conpot-lab.cfg",
        "conpot-json-log.py",
        "modbus-only-core.xml",
        "modbus-only-protocol.xml",
    )
    contents = {}
    for name in names:
        data = (assets / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest["files"][name]:
            raise ValueError("Asset hash mismatch: " + name)
        contents[name] = data

    expected_package = "/home/conpot/.local/lib/python3.8/site-packages/conpot"
    if (
        manifest["package_directory"] != expected_package
        or manifest["container_port"] != 5020
        or manifest["log_mount"] != "/conpot-json-logs"
    ):
        raise ValueError("Unexpected recipe runtime layout.")

    repository, digest = manifest["image"].split("@", 1)
    if repository != "ghcr.io/parasecurity/conpot":
        raise ValueError("Unexpected image repository.")
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise ValueError("Invalid image digest.")
    int(digest.removeprefix("sha256:"), 16)

    template = chart / "templates/deployment.yaml"
    original = template.read_text()
    if (
        ".Values.honeypots.conpot.image.repository" not in original
        or ".Values.honeypots.cowrie.image.repository" in original
        or ".Values.honeypots.dionaea.image.repository" in original
    ):
        raise ValueError("Expected a generated Conpot-only Deployment.")

    helper = chart.name + ".fullname"
    helpers = (chart / "templates/_helpers.tpl").read_text()
    if '"' + helper + '"' not in helpers:
        raise ValueError("Expected chart fullname helper was not found.")
    fullname = '{{ include "' + helper + '" . }}'

    config_template_name = "templates/conpot-config.yaml"
    protocol_template_name = "templates/conpot-modbus-template.yaml"
    checksum = (
        '{{ include (print $.Template.BasePath "/conpot-config.yaml") . '
        '| sha256sum }}'
    )
    protocol_checksum = (
        '{{ include (print $.Template.BasePath '
        '"/conpot-modbus-template.yaml") . | sha256sum }}'
    )

    changes = [
        (
            'spec:\n  {{- if not .Values.autoscaling.enabled }}',
            'spec:\n  strategy:\n    type: Recreate\n'
            '    rollingUpdate: null\n'
            '  {{- if not .Values.autoscaling.enabled }}',
        ),
        (
            '      {{- with .Values.podAnnotations }}\n'
            '      annotations: {{- toYaml . | nindent 8 }}\n'
            '      {{- end }}\n',
            '      annotations:\n'
            '        checksum/conpot-config: "' + checksum + '"\n'
            '        checksum/conpot-template: "' + protocol_checksum + '"\n'
            '        {{- with .Values.podAnnotations }}\n'
            '        {{- toYaml . | nindent 8 }}\n'
            '        {{- end }}\n',
        ),
        (
            '      serviceAccountName:',
            '      automountServiceAccountToken: false\n'
            '      serviceAccountName:',
        ),
        (
            '          ports:\n',
            '          args:\n'
            '            - "--template"\n'
            '            - "/etc/conpot-modbus"\n'
            '            - "-f"\n'
            '            - "--logfile"\n'
            '            - "/conpot-json-logs/conpot.log"\n'
            '            - "--temp_dir"\n'
            '            - "/tmp"\n'
            '          readinessProbe:\n'
            '            exec:\n'
            '              command: ["python3", "-c", "from pathlib import Path; import sys; target = \'00000000:%04X\' % int(sys.argv[1]); rows = Path(\'/proc/net/tcp\').read_text().splitlines()[1:]; sys.exit(0 if any(row.split()[1] == target and row.split()[3] == \'0A\' for row in rows) else 1)", "5020"]\n'
            '            initialDelaySeconds: 5\n'
            '            periodSeconds: 30\n'
            '            timeoutSeconds: 3\n'
            '          ports:\n',
        ),
        (
            '          volumeMounts:\n',
            '          volumeMounts:\n'
            '            - name: conpot-modbus-template\n'
            '              mountPath: /etc/conpot-modbus\n'
            '              readOnly: true\n'
            '            - name: conpot-config\n'
            '              mountPath: ' + expected_package + '/testing.cfg\n'
            '              subPath: conpot.cfg\n'
            '              readOnly: true\n'
            '            - name: conpot-config\n'
            '              mountPath: ' + expected_package + '/core/loggers/json_log.py\n'
            '              subPath: json_log.py\n'
            '              readOnly: true\n',
        ),
        (
            '      volumes:\n',
            '      volumes:\n'
            '        - name: conpot-modbus-template\n'
            '          configMap:\n'
            '            name: ' + fullname + '-template\n'
            '            items:\n'
            '              - key: core.xml\n'
            '                path: template.xml\n'
            '              - key: modbus.xml\n'
            '                path: modbus/modbus.xml\n'
            '        - name: conpot-config\n'
            '          configMap:\n'
            '            name: ' + fullname + '-config\n',
        ),
        (
            '            path: {{ .Values.volumes.conpothostPath }}',
            '            path: {{ .Values.volumes.conpothostPath }}\n'
            '            type: Directory',
        ),
    ]

    updated = original
    for old, new in changes:
        if updated.count(old) != 1:
            raise ValueError("Unexpected template structure near: " + repr(old))
        updated = updated.replace(old, new, 1)

    files = {
        config_template_name: (
            'apiVersion: v1\nkind: ConfigMap\nmetadata:\n'
            '  name: ' + fullname + '-config\n'
            'data:\n'
            '  conpot.cfg: |\n'
            '{{ .Files.Get "conpot-lab.cfg" '
            '| replace "__RELEASE_NAME__" .Release.Name | indent 4 }}\n'
            '  json_log.py: |\n'
            '{{ .Files.Get "conpot-json-log.py" | indent 4 }}\n'
        ),
        protocol_template_name: (
            'apiVersion: v1\nkind: ConfigMap\nmetadata:\n'
            '  name: ' + fullname + '-template\n'
            'data:\n'
            '  core.xml: |\n'
            '{{ .Files.Get "modbus-only-core.xml" | indent 4 }}\n'
            '  modbus.xml: |\n'
            '{{ .Files.Get "modbus-only-protocol.xml" | indent 4 }}\n'
        ),
    }

    values = {
        "honeypots": {
            "conpot": {
                "image": {
                    "repository": repository,
                    "tag": "latest@" + digest,
                    "pullPolicy": "IfNotPresent",
                },
                "ports": {
                    "namemodbus": "modbus",
                    "protocolmodbus": "TCP",
                    "portmodbus": service_port,
                    "containerPortmodbus": 5020,
                },
            }
        },
        "serviceAccount": {"automount": False},
        "replicaCount": 1,
        "autoscaling": {"enabled": False},
        "service": {"type": "NodePort", "extTrafficPolicy": "Local"},
        "volumes": {
            "conpotmountPath": "/conpot-json-logs",
            "conpothostPath": str(log_path),
        },
    }

    backup = chart.parent / (chart.name + "-deployment-before-recipe.yaml")
    values_path = chart.parent / (chart.name + "-recipe-values.json")
    test = chart / "templates/tests/test-connection.yaml"
    saved_test = chart.parent / (chart.name + "-unused-http-test.yaml")

    destinations = [
        backup, values_path,
        *(chart / name for name in names),
        *(chart / name for name in files),
    ]
    if test.exists():
        destinations.append(saved_test)
    if any(path.exists() for path in destinations):
        raise ValueError("Preparation output already exists; use a fresh chart.")

    # All structural checks above complete before the chart is changed.
    backup.write_text(original)
    for name, data in contents.items():
        (chart / name).write_bytes(data)
    for name, text in files.items():
        (chart / name).write_text(text)
    values_path.write_text(json.dumps(values, indent=2) + "\n")
    template.write_text(updated)
    if test.exists():
        test.rename(saved_test)

    print("Prepared chart:", chart)
    print("Required values file:", values_path)
    print("Required host log directory:", log_path)
    print("No deployment performed.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("chart", type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument(
        "--assets",
        type=Path,
        default=Path(__file__).resolve().parent / "assets/conpot-modbus",
    )
    args = parser.parse_args()
    try:
        prepare(args.chart, args.request, args.assets)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()

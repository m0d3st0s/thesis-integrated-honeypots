import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("chart", type=Path)
args = parser.parse_args()

try:
    chart = args.chart.resolve()
    if chart.name != "auto-mixed-01":
        raise ValueError("This helper supports only auto-mixed-01.")

    template = chart / "templates/deployment.yaml"
    original = template.read_text()

    selected = [
        name for name in ("cowrie", "dionaea")
        if ".Values.honeypots.{}.image.repository".format(name) in original
    ]
    if not selected:
        raise ValueError("No supported honeypot containers found.")

    for name in ("cowrie", "dionaea"):
        if name not in selected and name + "-state" in original:
            raise ValueError("Unexpected persistent volume for " + name)

    changes = [
        (
            'spec:\n  {{- if not .Values.autoscaling.enabled }}',
            'spec:\n'
            '  strategy:\n'
            '    type: Recreate\n'
            '    rollingUpdate: null\n'
            '  {{- if not .Values.autoscaling.enabled }}',
        ),
    ]

    mounts = {
        "cowrie": (
            "cowriemountPath",
            "cowrie-data",
            "/cowrie/cowrie-git/var/lib/cowrie",
        ),
        "dionaea": (
            "dionaeamountPath",
            "dioanea-data",
            "/opt/dionaea/var/lib/dionaea",
        ),
    }

    volume_block = "      volumes:\n"

    for name in selected:
        value, log_volume, data_path = mounts[name]
        old_mount = (
            "            - mountPath: {{ .Values.volumes." + value + " }}\n"
            "              name: " + log_volume
        )
        new_mount = (
            old_mount + "\n"
            "            - mountPath: " + data_path + "\n"
            "              name: " + name + "-state"
        )
        changes.append((old_mount, new_mount))

        volume_block += (
            "        - name: " + name + "-state\n"
            "          hostPath:\n"
            "            path: /var/lib/thesis-honeypots/auto-mixed-01/"
            + name + "\n"
            "            type: Directory\n"
        )

    changes.append(("      volumes:\n", volume_block))

    if all(new in original for old, new in changes):
        print("Persistent storage already configured.")
    else:
        updated = original
        for old, new in changes:
            if updated.count(old) != 1 or new in updated:
                raise ValueError(
                    "Unexpected or partially prepared template. "
                    "Use a freshly generated chart."
                )
            updated = updated.replace(old, new, 1)

        backup = chart.parent / "deployment-before-stateful-storage.txt"
        with backup.open("x") as output:
            output.write(original)

        template.write_text(updated)
        print("Persistent storage configured for:", ", ".join(selected))

    test = chart / "templates/tests/test-connection.yaml"
    if test.exists():
        destination = chart.parent / "unused-http-test.yaml"
        if destination.exists():
            raise ValueError("Default-test backup already exists.")
        test.rename(destination)
        print("Moved the unsuitable default HTTP test outside the chart.")

except (OSError, ValueError) as exc:
    parser.exit(1, "Error: {}\n".format(exc))

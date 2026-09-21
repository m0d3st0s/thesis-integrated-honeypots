import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("chart", type=Path)
args = parser.parse_args()

try:
    chart = args.chart.resolve()
    if chart.name != "auto-mixed-01":
        raise ValueError("This lab helper supports only auto-mixed-01.")

    template = chart / "templates/deployment.yaml"
    original = template.read_text()

    changes = [
        (
            'spec:\n  {{- if not .Values.autoscaling.enabled }}',
            'spec:\n'
            '  strategy:\n'
            '    type: Recreate\n'
            '    rollingUpdate: null\n'
            '  {{- if not .Values.autoscaling.enabled }}',
        ),
        (
            '            - mountPath: {{ .Values.volumes.dionaeamountPath }}\n'
            '              name: dioanea-data',
            '            - mountPath: {{ .Values.volumes.dionaeamountPath }}\n'
            '              name: dioanea-data\n'
            '            - mountPath: /opt/dionaea/var/lib/dionaea\n'
            '              name: dionaea-state',
        ),
        (
            '      volumes:\n',
            '      volumes:\n'
            '        - name: dionaea-state\n'
            '          hostPath:\n'
            '            path: /var/lib/thesis-honeypots/auto-mixed-01/dionaea\n'
            '            type: Directory\n',
        ),
    ]

    # Allow repeat execution, but reject unexpected template changes.
    if all(new in original for old, new in changes):
        print("Persistence configuration already present.")
    else:
        updated = original
        for old, new in changes:
            if updated.count(old) != 1 or new in updated:
                raise ValueError(
                    "Unexpected or partially modified template; "
                    "deployment template left unchanged."
                )
            updated = updated.replace(old, new, 1)

        backup = chart.parent / "deployment-before-persistence.txt"
        with backup.open("x") as output:
            output.write(original)

        template.write_text(updated)
        print("Added persistent Dionaea storage and Recreate strategy.")

    test = chart / "templates/tests/test-connection.yaml"
    if test.exists():
        saved_test = chart.parent / "unused-http-test.yaml"
        if saved_test.exists():
            raise ValueError("Test backup already exists; refusing to overwrite.")
        test.rename(saved_test)
        print("Moved the unsuitable default HTTP test outside the chart.")

except (OSError, ValueError) as exc:
    parser.exit(1, "Error: {}\n".format(exc))

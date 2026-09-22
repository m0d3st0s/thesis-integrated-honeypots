# Integrated network discovery and honeypot system

Thesis lab prototype integrating Nmap discovery, evidence-based service selection,
HoneyChart generation, Helm/K3s deployment, persistent storage, and reporting.
Supported recipes are SSH (Cowrie), HTTP (Dionaea), and Modbus (Conpot).
Shared honeypots emulate services, not complete target-device identities.

## Start here

See [the reproduction guide](docs/reproduction-guide.md) for prerequisites,
configuration, execution, verified results, and remaining validation work.

The current orchestration entry point is `run_system.py`:

```bash
python3 run_system.py \
  --scan-config /path/to/scan.json \
  --catalog config/service-catalog.json \
  --deployment-config /path/to/deployment.json \
  --runtime-config /path/to/runtime.json \
  --output /path/to/new-run-directory \
  --mode prepare
```

Modes:

- `prepare` (default): discover services and prepare/validate charts.
- `install`: discover, prepare, initialize fresh storage, and install new releases.
- `upgrade`: discover, prepare, and upgrade compatible existing releases.
- `--deploy` is a compatibility alias for upgrade; it is mutually exclusive with `--mode`.

To install already prepared charts:

```bash
python3 install_prepared.py /path/to/prepared \
  --output /path/to/new-installation-directory --install
```

Without `--install`, the installer validates chart/release prerequisites; node-side
storage emptiness is checked during installation. Existing releases and nonempty
initialization roots are refused. Installation requires an existing, configured
Kubernetes cluster, namespace, node, and accessible pinned images.

## Reporting

Use an explicit schema-version-2 configuration with source paths, deployment
names, namespace, source identities, label files, and kubeconfig:

```bash
python3 report_config.py --config /path/to/reporting.json \
  --output /path/to/new-report-directory \
  2026-09-22T00:00:00Z 2026-09-23T00:00:00Z

python3 report_config.py --config /path/to/reporting.json --previous-day
```

`generate_report_units.py` generates and validates configurable systemd units;
it does not install them. Reporting does not require the HoneyChart server.

`deploy.sh` and the earlier pipeline scripts are legacy entry points.
`report.sh` without `--config` retains the legacy mixed-report interface.
Use the explicit Python commands above for the current configurable workflow.

## Configuration and storage

Repository configurations describe the original lab. Copy and adapt them for a
new environment; in particular update scanner IP/exclusions, interface, node
hostname, source identities, label paths, and kubeconfig.

- `config/lab-scan.json`: discovery scope and protocol probes.
- `config/service-catalog.json`: service-to-honeypot selection rules.
- `config/lab-deployment.json`: namespace, release mappings, ports, log root.
- `config/runtime.json`: HoneyChart endpoint, node, state root, image pins.
- `config/reporting.json`: reporting sources and explicit identities.
- `image-pins.yaml` and `assets/conpot-modbus/manifest.json`: pinned recipe images.
- `assets/honeychart/`: upstream revision, compatibility patch, dependency lockfile.

The lab defaults use `/var/lib/thesis-honeypots` for state and
`/var/log/honeypots` for logs. Evidence is stored under `~/thesis/runs`.
The report root is configurable. Node-local storage requires the configured node.
Read actual NodePorts from Kubernetes Services after each deployment.

## Validation and limitations

A separate Ubuntu VM reproduced fresh discovery, chart preparation, first
installation, external protocol tests, matched server evidence, and classified
reporting on 22 September 2026. A manual systemd report also passed. The first
automatic timer execution was still pending when this documentation was written.
See the guide for the exact environment and evidence locations.

- Discovery covers configured ports and responding targets only.
- A simulated Modbus target was used; these tests do not establish physical ICS compatibility.
- SSH/HTTP metrics count incoming connection starts, not confirmed attacks.
- Conpot logged starts remain separate from SSH/HTTP counts; session metadata can be reused.
- Controlled tests do not demonstrate attacker preferences.
- Report windows do not guarantee complete collection coverage.
- Configuration observations do not prove an event's external destination port.
- Releases are processed sequentially; the workflow is not a transaction across releases.
- Fresh-VM reproduction is not proof of portability across arbitrary architectures or platforms.

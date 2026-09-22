# User guide

Start with the [prerequisite guide](prerequisites.md). This page assumes tools,
HoneyChart, the Kubernetes node, namespace, policy, and user kubeconfig are ready.
Run commands as the account that will collect reports, on the storage node.

## Initialize a workspace

The example below matches the handoff lab. Replace network addresses, interface,
node name, exclusions, paths and timezone with your own values. The scanner must
have its configured IPv4 address on the chosen interface. Exclusions must belong
to the configured network; initialization also excludes the scanner itself.

```bash
python3 ~/thesis/integrated-system/honeypotctl.py init \
  --workspace "$HOME/thesis/honeypot-workspace" \
  --network 192.168.77.0/24 \
  --interface enp0s8 \
  --scanner-ip 192.168.77.12 \
  --exclude 192.168.77.10 \
  --exclude 192.168.77.11 \
  --node-hostname thesis-handoff \
  --kubeconfig "$HOME/.kube/thesis-k3s.yaml" \
  --namespace honeypots \
  --mixed-release handoff-mixed \
  --conpot-release handoff-modbus \
  --state-root /var/lib/thesis-honeypots/handoff \
  --log-root /var/log/honeypots/handoff \
  --timezone Europe/Athens
```

`init` creates a new private workspace, copies recipe configuration and image
pins, assigns a unique identity, and creates empty label files. It performs no
scan, dependency installation, storage initialization, or cluster mutation.
It refuses an existing workspace path. Use dedicated, empty storage roots for a
first installation; do not substitute a directory containing valuable state.

Release names must be distinct lowercase Kubernetes-style names of 3–20
characters. State/log roots must be separate absolute dedicated paths. Keep
project/workspace paths simple: scheduling rejects systemd expansion/quoting
characters such as percent signs, dollar signs, quotes and backslashes.

Default HoneyChart endpoint: `http://127.0.0.1:8081/custom_build_endpoint`.
Override it during `init` with `--honeychart-endpoint`. Do not embed credentials
in the URL, because configuration is copied into run evidence.

For subsequent commands in this terminal:

```bash
export PROJECT="$HOME/thesis/integrated-system"
export WORKSPACE="$HOME/thesis/honeypot-workspace"
export KUBECONFIG="$HOME/.kube/thesis-k3s.yaml"
```

## Review configuration and check prerequisites

```bash
cat "$WORKSPACE/scan.json"
python3 "$PROJECT/honeypotctl.py" check --workspace "$WORKSPACE"
```

Default TCP scan ports are 22, 80, 443, 445, 502 and 1502; Modbus probes target
502 and 1502. The HTTPS/SMB extension adds explicit SMB probes on open TCP 445
using `smb-protocols`; `smb_probe_ports` must be a subset of `tcp_ports`.
HTTPS selection needs a probed HTTP service with TLS tunnel evidence.
Edit `scan.json` before running if your authorized scope differs.
Selection rules live in `catalog.json`; deployment mappings in `deployment.json`;
HoneyChart, image-pin location and node placement in `runtime.json`.
Changing a catalog alone does not implement an additional supported recipe.

HTTPS and repaired SMB1 passed the [recorded lab checks](protocol-validation.md).
Follow [their validation guide](https-smb.md) for your installation, with a fresh workspace and dedicated
release/storage names. Updating project files does not migrate existing
workspaces. Do not rerun `init` over an existing workspace.

The check reads versions, local addresses, node readiness/architecture, namespace,
policy configuration, HoneyChart HTTP availability, and bundled-asset hashes.
It does not scan or mutate the cluster. It cannot prove every image can be pulled,
all later RBAC operations will succeed, storage is empty/writable, protocols work,
or the network policy is enforced. Preparation and runtime checks cover later
stages, and external acceptance checks test observed behavior.

Current storage access requires UID 0 or 1000, or membership in group 1000.
The checker rejects other node architectures than Linux amd64 and requires a
unique ready, schedulable node whose hostname label matches configuration and
whose InternalIP belongs to this machine. Additional egress-allow policies are
refused. See [troubleshooting](troubleshooting.md) for failed checks.

## Install

Keep HoneyChart running. Ensure the intended targets and services are available;
a stopped target is absent from discovery and may change selection.
For the three-service lab, see the target checklist in
[acceptance checks](acceptance-checks.md#target-checklist).

```bash
(
set -euo pipefail
umask 077
CHECK=$(mktemp -d "$WORKSPACE/runs/install-console-XXXXXXXX")
python3 "$PROJECT/honeypotctl.py" run \
  --workspace "$WORKSPACE" --mode install \
  2>&1 | tee "$CHECK/console.log"
)
```

One command checks prerequisites, discovers devices/services, profiles/selects,
generates and validates charts, initializes fresh storage, installs releases,
checks runtime state, publishes reporting configuration and collects a report.
It may prompt for sudo credentials. First image downloads can take several minutes.

Each operation records `runs/run-*/workflow.json` and stage logs. Follow the
printed run path; it is not the optional `install-console-*` transcript folder.
Success ends with `Workflow status: completed`. Check actual workloads and ports:

```bash
kubectl get pods,svc -n honeypots \
  -l 'app.kubernetes.io/instance in (handoff-mixed,handoff-modbus)'
```

Replace names if you chose different releases. NodePorts are allocated values;
read them from the live Services rather than reusing historical examples.
The initial report covers midnight in the workspace timezone through collection
initiation. A zero-interaction report is expected before traffic arrives.

## Prepare or upgrade

Prepare without deployment or storage initialization:

```bash
python3 "$PROJECT/honeypotctl.py" run --workspace "$WORKSPACE" --mode prepare
```

This still scans, calls HoneyChart and performs server-side validation.
`prepare` is the default mode when `--mode` is omitted.

Rescan and upgrade a successfully installed workspace:

```bash
python3 "$PROJECT/honeypotctl.py" run --workspace "$WORKSPACE" --mode upgrade
```

A second install of an already published workspace is refused. Upgrade requires
that workspace's successful installation; it does not adopt arbitrary existing
Helm releases. Keep the workspace identity, namespace, release mappings and
storage roots unchanged. Do not retarget its kubeconfig to a different cluster.

The upgrade path is conservative. A plan requiring both a new release and an
existing release is refused by the underlying preflight. Adding a previously
absent container can require supported retained storage; arbitrary bootstrap of
new container state during upgrade is not provided. Whole releases no longer
selected remain installed. The new report configuration follows selection;
archived previous configurations retain the old source definitions.

Releases are processed sequentially. A failure can leave partial live changes;
there is no transaction across releases or automatic destructive cleanup.
If no targets are discovered, existing deployment/reporting configuration is
retained. Ambiguous or unsupported evidence can prevent preparation.

## Report

```bash
python3 "$PROJECT/honeypotctl.py" report --workspace "$WORKSPACE" \
  --since 2026-09-22T00:00:00+03:00 \
  --until 2026-09-23T00:00:00+03:00

python3 "$PROJECT/honeypotctl.py" report \
  --workspace "$WORKSPACE" --previous-day
```

The dated command is an example: choose a window containing your actual events.
All explicit timestamps need offsets (`Z` is UTC); the start is inclusive and
end exclusive. `--previous-day` uses the configured calendar timezone, default UTC.
Do not combine it with `--since` / `--until`. Reports collected before the end
of a window contain evidence available at collection time, not future activity.

Add `--output /path/to/new/directory` to choose the report destination. Otherwise,
a unique directory is created under `WORKSPACE/reports`. The report command does
not require Nmap or HoneyChart. It needs Kubernetes metadata access and local
read access to the selected source files.

Schema-version-2 `reporting.json` is generated after successful deployment.
It selects the requested honeypot sources and mixed protocols. The extension
supports separate HTTP, HTTPS and SMB selection in Dionaea, alongside SSH in
Cowrie and the separate Modbus report. The original three protocols passed live
acceptance; HTTPS and repaired SMB1 also passed live protocol and event-correlation
checks. SMB2/SMB3 emulation and SMB authentication/file operations are not validated.
An omitted source is `not_selected`;
a selected source that is missing or malformed causes failure, not a zero count.
The configuration supports at most one mixed release and one Conpot release.

Database/log identities are workspace-specific and stable across upgrades. They
must not be reused after resetting or replacing the underlying source storage.
Copying old lab labels into a new database can misclassify unrelated records.

### Metrics and labels

Mixed-service reports count incoming connection starts. The legacy output folder
`ssh-http/` and manifest key `ssh_http` are retained for compatibility and can now
also contain HTTPS and SMB. New reporting configurations contain
`mixed.protocols`, for example `["https", "smb"]` with
`mixed.services: ["dionaea"]`. Other/unknown protocol starts are counted as excluded
from the selected total and remain in `all-connections.json`. Legacy
configurations without `mixed.protocols` retain all selected-source records.

Dionaea records are identified from their protocol and transport: `httpd/tcp`
is HTTP, `httpd/tls` is HTTPS, and `smbd/tcp` is SMB. Port numbers alone do not
establish TLS. A connection-start record does not prove a successful application
exchange; use external protocol tests for that. Conpot reports logged
`NEW_CONNECTION` records separately, plus payload/record counts. They are not
summed into a single connection total. Session timestamps/endpoints in Conpot
may be reused; window membership uses reported session creation time.

Events begin unclassified. Optional controlled-test labels require independent
client/server correlation. Mixed labels in `labels/mixed.txt` identify exact
normalized event IDs. Conpot labels in `labels/conpot.json` identify a start
record, a supporting payload record and matching client exchange. Use exported
IDs, which include byte offsets/hashes; do not fabricate them from reserialized
JSON. [Acceptance checks](acceptance-checks.md) explains how to collect evidence.

Unclassified does not mean malicious. Controlled tests do not show attacker
preferences. Snapshots do not prove full-window coverage, and Service metadata
alone does not prove an event's historical external destination port.

## Schedule and change timezone

For a successfully installed workspace:

```bash
(
set -euo pipefail
CHECK=$(mktemp -d "$WORKSPACE/runs/schedule-XXXXXXXX")
python3 "$PROJECT/honeypotctl.py" schedule --workspace "$WORKSPACE" \
  --time 00:10 --output "$CHECK/units" --install
)
```

The time is interpreted in the reporting configuration timezone. Omit `--install`
to generate/validate units only. Each output directory must be new. Systemd is
required only for scheduling. See [reporting timezones](reporting-timezones.md)
for verification, changing existing timers, temporary tests and missed executions.
Daily reports do not trigger scans or upgrades.

## Evidence and recovery

The workspace contains configuration, `labels/`, `runs/`, `reports/`,
`reporting.json` after installation, and `active-deployment.json` recording the
last successful deployment publication. Run directories contain prerequisite
results, stage logs, proposed reporting settings, and underlying pipeline evidence.
External source data lives under your configured state/log roots.

If reporting fails after deployment, `workflow.json` preserves
`deployment_status: completed` and the active reporting configuration. Fix the
source/access problem and use `report`; do not reinstall. If deployment partially
fails, inspect saved manifests, Helm state and logs before recovery.

Workspace commands share an operation lock. Scheduled reports fail visibly when
another operation holds it; they do not queue indefinitely. Direct legacy commands
do not share this workspace lock: avoid concurrent operations on the same releases.

## Lower-level and legacy commands

- `run_system.py`: staged discovery/preparation/install/upgrade without the new
  workspace wrapper's automatic reporting publication. Its `--deploy` flag is
  a compatibility alias for `--mode upgrade`.
- `prepare_run.py`: prepare charts from saved discovery evidence.
- `install_prepared.py`: install already prepared charts with `--install`;
  without that flag it performs its validation path. Storage emptiness is checked
  during actual initialization.
- `deploy_prepared.py`: compatible upgrades of prepared existing releases.
- `report_config.py --config ...`: direct configured reporting.
- `generate_report_units.py`: generate/validate units only, without installation.
- `report.sh --config ...`: forwards to configured reporting; without `--config`
  it retains the legacy mixed-report interface.
- `daily_report.sh`: uses `THESIS_REPORT_CONFIG` or original-lab reporting defaults.
- `deploy.sh` / versioned pipeline scripts and `systemd/`: historical lab paths.

Use each script's `--help` for arguments. New users should start with the workspace
CLI, not the checked-in original-lab configuration or static systemd units.

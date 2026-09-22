# Reproduction guide and observed results

## Purpose and status

This guide records the separate-VM reproduction performed on 22 September 2026
and provides the commands for the configurable pipeline. It covers a fresh
controller/honeypot VM using existing controlled lab targets. Host prerequisites
were installed manually; the project installer bootstraps honeypot storage and
releases, not Ubuntu or Kubernetes.

Verified: fresh discovery, preparation, installation, external protocol responses,
server/client evidence correlation, classified reporting, and manual systemd
execution. Automatic timer execution remains pending. Reproduction used the
staged prepare-then-install workflow; it did not test `run_system.py --mode install`
as a single uninterrupted command on this new VM.

## Recorded environment

| Component | Observed value |
| --- | --- |
| Integration source | `6ac744f53aa78fa667a84db672c83228349d9b2a` |
| HoneyChart upstream | `6522d81d71a38df86de9da409a83acbbcd3a267e` |
| VM / user | `thesis-repro` / `researcher` |
| Ubuntu | 24.04.5 LTS, upgraded from the installed 24.04.2 image |
| Kernel | `7.0.0-31-generic` |
| Architecture | x86_64 |
| VM allocation | 2 virtual CPUs, approximately 6 GiB RAM, 40 GB disk |
| Python | 3.12.3 |
| Nmap | 7.94SVN |
| Node / npm | v24.21.0 / 11.19.0 |
| Helm | v3.22.0+g144ca65 |
| K3s | v1.36.4+k3s1 |

These are observed versions, not a tested compatibility range. Documentation
changes after the recorded source commit do not change which revision was tested.

## Network and target prerequisites

| VM | Lab address | Role |
| --- | --- | --- |
| thesis-repro | 192.168.77.11 | Scanner, HoneyChart, standalone K3s, honeypots |
| thesis-target | 192.168.77.20 | SSH and nginx HTTP; external protocol-test client |
| thesis-target-2 | 192.168.77.21 | SSH and simulated Modbus on TCP 1502 |
| Original controller | 192.168.77.10 | Excluded from reproduction discovery |

VirtualBox NAT on `enp0s3` supplies internet access; `enp0s8` connects to the shared
internal lab network `thesis-lab`. The lab adapter has no default route. The new
controller is an independent cluster and does not join the original cluster.
Use only the authorized lab subnet for discovery.

Confirm the first target has SSH and nginx active. On the second target start the
existing simulator in a terminal that remains open:

```bash
cd ~/thesis/ics-simulator
./.venv/bin/python modbus_target.py
```

Verify `192.168.77.21:1502` is listening. The existing simulator environment and
script on that target are prerequisites; this guide does not establish that the
integration repository installs the target simulator. General Nmap detection may
name port 1502 `shivadiscovery?`; selection must use the subsequent positive Modbus
probe evidence rather than that port-table guess.

## Controller prerequisites

Install Git, Python 3, Nmap, curl, CA certificates, xz utilities, zip, and unzip.
Install Node, Helm, and K3s at the recorded versions. The observed Node installation
used the official Linux x64 archive and checked it against published SHA-256
checksums. The Helm Linux amd64 archive was also checksum verified. Save the
installation transcripts and checksums alongside the experiment evidence.

Official setup references:

- Node archive: https://nodejs.org/dist/v24.21.0/
- Helm release: https://github.com/helm/helm/releases/tag/v3.22.0
- K3s configuration: https://docs.k3s.io/installation/configuration
- K3s cluster access: https://docs.k3s.io/cluster-access

Clone the integration repository into `~/thesis/integrated-system`. Record its
commit and working-tree status. For exact repetition of this experiment, use the
recorded integration commit above in a dedicated checkout.

### Reconstruct HoneyChart

Read `assets/honeychart/manifest.json`. Verify each listed asset against its SHA-256
hash. Clone the recorded repository into `~/thesis/honeychart`, check out the
manifest's exact commit, run `git apply --check` and then apply
`assets/honeychart/compatibility.patch`. Copy the supplied `package-lock.json` into
the checkout. Run `npm ci --no-audit --no-fund` and verify the lockfile hash remains
unchanged. Use the integration repository's absolute asset paths when working
inside the HoneyChart checkout.

Configure HoneyChart's `host.json` separately:

```json
{"host": "127.0.0.1", "port": "8081"}
```

The compatibility patch removes the development nodemon dependency and adds the
`httpRoute.enabled: false` chart value. Changes to `host.json`, `package.json`, and
`src/create_charts.js` are therefore expected in the reconstructed checkout.

Start it in a separate terminal:

```bash
cd ~/thesis/honeychart
npm start
```

A GET to `http://127.0.0.1:8081/` returned HTTP 200. Successful chart generation in
the preparation stage is the stronger check of the build endpoint.

### Configure standalone K3s

The reproduction used `/etc/rancher/k3s/config.yaml` with:

```yaml
node-name: thesis-repro
node-ip: 192.168.77.11
advertise-address: 192.168.77.11
flannel-iface: enp0s8
write-kubeconfig-mode: "0600"
disable:
  - traefik
  - servicelb
```

Install with `INSTALL_K3S_VERSION='v1.36.4+k3s1'` using the official installer in
server mode. Preserve the downloaded installer and installation log. Wait for the
node to exist before waiting for its Ready condition: the first attempt observed
`nodes "thesis-repro" not found` while registration was still in progress. A later
check confirmed Ready at `192.168.77.11`, with all three system pods running.

Copy the admin kubeconfig to `~/.kube/thesis-k3s.yaml`, owned by the local user with
mode 0600; keep `~/.kube` mode 0700. Export this for kubectl, Helm, and pipeline tools:

```bash
export KUBECONFIG="$HOME/.kube/thesis-k3s.yaml"
```

Persist the export in the user's shell configuration. Do not publish kubeconfig
contents or cluster tokens. This is an administrative credential. Copied
kubeconfigs need updating when their embedded credentials are renewed.

### Namespace and outbound policy

Apply the following before installing honeypots:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: honeypots
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-outbound
  namespace: honeypots
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress: []
```

Policy existence alone does not demonstrate enforcement. The observed enforcement
test is recorded below. Do not disable the policy to make honeypot outbound tests
succeed.

## Adapt configuration without changing lab defaults

Create a separate `~/thesis/reproduction-config` directory. Copy the values from
`config/lab-scan.json`, `config/lab-deployment.json`, and `config/runtime.json` into
`scan.json`, `deployment.json`, and `runtime.json` respectively, with these changes:

- Scan: `scanner_ip` = `192.168.77.11`, `exclude_ips` = both `.10` and `.11` addresses.
- Keep network `192.168.77.0/24`, interface `enp0s8`, TCP ports
  `[22, 80, 443, 445, 502, 1502]`, Modbus probe ports `[502, 1502]`.
- Runtime: `node_hostname` = `thesis-repro`; use an absolute path to the repository's
  `image-pins.yaml`, resolving the original path relative to the original config.
- Keep HoneyChart endpoint `http://127.0.0.1:8081/custom_build_endpoint`.
- Deployment: retain namespace `honeypots`, release mappings, and log root for
  this independent cluster. Runtime state root remains `/var/lib/thesis-honeypots`.

The releases are `auto-mixed-01` (Cowrie and Dionaea) and `ics-modbus-01` (Conpot).
Fresh initialization roots must be empty. Node-local paths bind persistent storage
to the configured node. Do not reuse a production storage root for a fresh test.

## Discover and prepare

Run on the new controller, with HoneyChart and both targets available:

```bash
set -euo pipefail
umask 077
PROJECT="$HOME/thesis/integrated-system"
CONFIG="$HOME/thesis/reproduction-config"
RUN=$(mktemp -d "$HOME/thesis/runs/reproduction-XXXXXXXX")
export KUBECONFIG="$HOME/.kube/thesis-k3s.yaml"
sudo -v
python3 "$PROJECT/run_system.py" \
  --scan-config "$CONFIG/scan.json" \
  --catalog "$PROJECT/config/service-catalog.json" \
  --deployment-config "$CONFIG/deployment.json" \
  --runtime-config "$CONFIG/runtime.json" \
  --output "$RUN/system" --mode prepare \
  2>&1 | tee "$RUN/console.log"
```

Create `~/thesis/runs` beforehand if absent. Record `$RUN` for later terminals.
This experiment's directory was `~/thesis/runs/reproduction-Dsp4WrfQ`.

Inspect discovery evidence and generated requests. Expected selections in this
lab are Cowrie/Dionaea for the mixed release and Conpot for Modbus. Require
successful preparation, Helm lint, template rendering, and server dry-run checks.
Preparation does not install releases or initialize storage.

## Install prepared releases

Use the existing prepared directory, avoiding an unnecessary second scan:

```bash
python3 "$PROJECT/install_prepared.py" "$RUN/system/prepared" \
  --output "$RUN/installation" --install \
  2>&1 | tee "$RUN/installation-console.log"
kubectl get pods,svc -n honeypots
```

Use a new output directory. The installer checks absent releases and empty roots,
initializes recipe-specific directories, installs releases sequentially, and runs
runtime checks. If it fails, inspect saved evidence before retrying; a partial
installation may leave releases or initialized storage. Do not delete retained
state merely to bypass a refusal.

The observed result was mixed pod 2/2 Ready and Modbus pod 1/1 Ready, zero restarts,
and successful runtime checks for both releases. The preflight checker's message
`No deployment performed` refers to that checker, not the preceding installation.

Read NodePorts from live Services. Observed values below are historical, not fixed:

| Service | NodePort | Container port |
| --- | --- | --- |
| HTTP | 31061 | 80 |
| SSH | 31038 | 2222 |
| Modbus | 31039 | 5020 |

## Validate connectivity and logging

### Outbound evidence

The controller connected to the known target listener `192.168.77.20:80`.
Connections from all three honeypot containers returned `Connection refused`.
Three additional Conpot attempts corresponded to increases of three packets in
its `deny-outbound` policy path and three in its pod firewall REJECT rule, whose
action was `icmp-port-unreachable`.

This supports policy rejection for the tested Conpot TCP traffic. The initial
failures for Cowrie and Dionaea were observed but were not separately attributed
using per-pod counter comparisons. Do not claim all-destination or all-protocol
isolation from this experiment.

Evidence: `~/thesis/runs/egress-counter-check-8ccxhifw` and the main run's
`outbound-connectivity-check.json`.

### External protocol checks

Run controlled tests from `thesis-target` at `192.168.77.20`, using the new
controller `.11` and the current Service NodePorts. Bind the client source address
explicitly to avoid accidentally testing locally. An earlier execution on the
wrong VM failed at source-address binding before making a connection.

| Protocol | Observed test and result |
| --- | --- |
| HTTP | GET `/thesis-reproduction-check`; HTTP/1.1 404 Not Found |
| SSH | Banner `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2` |
| Modbus | Read Coils request `000100000006010100010008`; full reply `000100000004010101e4` |

The coil byte is observed data, not a universal expected constant. Verify the
transaction ID, protocol ID, unit, function, byte count, and complete framing.
An SSH banner check is not a test of login or shell interaction.

At approximately `2026-09-22T09:52:20Z`, the client source ports and server records
matched as follows:

| Protocol | Client source port | Server identifier |
| --- | --- | --- |
| HTTP | 37825 | Dionaea connection 1 |
| SSH | 35647 | Cowrie session `1492d8637347` |
| Modbus | 38323 | Session `3f13c967-1f90-4179-a3be-fe13d67c6482` |

The Modbus request and response payload also matched. Its three records represent
start, payload, and disconnect, not three connections. Server timestamps and
client timestamps came from separate VM clocks; they are not latency measurements.

Client evidence is on `thesis-target` at
`/home/mod/thesis/runs/repro-protocol-check-iv3mnvSV/protocol-check.txt`.
Server correlation evidence is in the main run's
`protocol-evidence-ZwgTdKDB/matching-events.txt`. Preserve the client file separately;
its path in a label does not copy it to the controller.

## Reporting with independent source identities

Copy the schema-version-2 reporting configuration into the experiment directory.
Keep source paths appropriate for the new installation, and configure its own
kubeconfig, report root, history root, and label files. Do not copy original lab
controlled-test labels into the fresh database.

The reproduction configuration is `$RUN/reporting/reporting.json` and uses:

- Database ID: `thesis-repro-Dsp4WrfQ-dionaea-initial`.
- Conpot log ID: `thesis-repro-Dsp4WrfQ-conpot-json-001`.
- Mixed labels: `$RUN/reporting/mixed-labels.txt`.
- Conpot labels: `$RUN/reporting/conpot-labels.json`.
- Reports root: `$RUN/reporting/reports`.

For a new experiment choose new IDs; keep them stable for the lifetime of that
source. Start with empty mixed labels and Conpot `{"schema_version":1,"events":[]}`.
Collect a baseline, correlate normalized events with client evidence, then add
only the verified IDs to labels. Conpot labels identify a start and supporting
payload event; IDs depend on byte offset and SHA-256 of the exact raw line,
including its newline. Use the exporter, not reconstructed JSON, to obtain them.

```bash
python3 "$PROJECT/report_config.py" \
  --config "$RUN/reporting/reporting.json" \
  --output "$RUN/reporting/classified" \
  2026-09-22T00:00:00Z 2026-09-23T00:00:00Z
```

Use a new output directory each time. The verified report contains HTTP 1 and SSH 1,
both controlled; Modbus 1 controlled logged start, 1 payload record, 3 total log
records, no unclassified starts, and no missing labels. SSH/HTTP and Modbus metrics
remain separate. A report collected before the window closes is evidence available
at collection time, not proof of complete coverage of the requested day.

Preserve the baseline and classified outputs, snapshots, manifests, and labels.

## Daily reporting

Generate units using the reproduction configuration and actual local user:

```bash
python3 "$PROJECT/generate_report_units.py" \
  --project "$PROJECT" --config "$RUN/reporting/reporting.json" \
  --user "$(id -un)" --utc-time 00:10 \
  --output "$RUN/reporting/systemd-units"
```

After successful validation, back up any existing same-name units. Install the
service and timer into `/etc/systemd/system` with mode 0644, run daemon-reload,
enable/start the timer, and manually start the service. Preserve these outputs:

```bash
systemctl show thesis-daily-report.service -p Result -p ExecMainStatus --no-pager
systemctl list-timers --all thesis-daily-report.timer --no-pager
sudo journalctl --utc -u thesis-daily-report.service --no-pager
```

Observed: the manual service returned success/0 and reported September 21 UTC with
zero events, as expected. Units used user/group `researcher`, the correct HOME and
configuration, UMask 0077, and an explicit Python executable. The timer was enabled
for September 23 at 00:10 UTC (03:10 EEST), with no previous firing at observation.

**Pending:** preserve the first automatic execution's journal and resulting
September 22 report. Keep the VM running and host awake for the scheduled test.
Do not treat the prior manual success as evidence that the timer fired. Update
this status only after observing the result.

## Evidence preservation and known issues

The main run contains discovery/preparation outputs under `system`, installer
outputs under `installation`, reporting baseline/classified results under
`reporting`, and environment/commit/patch records under
`reproducibility-record-q5DTtH0z`. Manual service evidence is under
`reporting/systemd-check-MdUQnbUn`. The counter evidence and client transcript are
outside the main run; include them when archiving the experiment. Keep credentials
out of public evidence bundles.

The new VM emitted warnings that the K3s kubectl wrapper could not read
`/etc/rancher/k3s/config.yaml`. Commands still succeeded using the user's kubeconfig.
The warning remained unresolved during this experiment; it was not a failed API
authentication. Do not confuse the server configuration with the user's kubeconfig.

Helm-managed resources also emitted missing last-applied-annotation warnings during
server dry-run validation. Validation passed; these messages are not proof of a
live apply mutation. An optional source-search command failed because ripgrep was
absent; Python was used instead, so ripgrep was not a runtime prerequisite.

This exercise establishes reproduction in the recorded environment with manual
prerequisite setup. It does not establish cross-platform portability, unattended
host provisioning, physical ICS fidelity, or continuous availability. A maintained
standalone setup script and further platform tests would be separate work.

# Integrated network discovery and honeypot system

A Linux command-line research prototype that discovers network services, selects
supported honeypots, generates and validates Helm charts through HoneyChart,
deploys them to Kubernetes, and collects reports from their persistent data.

| Observed service | Honeypot recipe |
| --- | --- |
| SSH | Cowrie |
| HTTP | Dionaea |
| Modbus, supported by the protocol probe | Conpot |

Selection uses configured rules and observed service evidence. Shared honeypots
emulate services; they do not clone complete devices or create one honeypot per
observed host. Other discovered services do not automatically gain a recipe.

## Start here

1. [Prepare prerequisites](docs/prerequisites.md): Linux, tools, HoneyChart,
   Kubernetes, local storage access, namespace and network policy.
2. [Configure and run](docs/user-guide.md): initialize a workspace, check it,
   install, report, and perform compatible upgrades.
3. [Schedule reports](docs/reporting-timezones.md): optional daily reporting in
   UTC or an IANA timezone such as `Europe/Athens`.
4. [Validate your installation](docs/acceptance-checks.md): external protocol
   responses, server-record correlation, outbound-policy evidence, and archiving.
5. [Troubleshoot](docs/troubleshooting.md) using the saved run evidence.

The user-facing entry point is `python3 honeypotctl.py`:

| Command | Effect |
| --- | --- |
| `init` | Creates a new configuration workspace; installs no dependencies |
| `check` | Checks prerequisites without scanning or changing cluster resources |
| `run --mode prepare` | Scans, profiles, selects, and prepares/validates charts |
| `run --mode install` | Runs preparation, initializes fresh storage, installs, checks runtime state, and collects an immediate report |
| `run --mode upgrade` | Rescans, prepares, upgrades compatible existing releases, checks state, and reports |
| `report` | Collects an explicit window or the previous configured calendar day |
| `schedule` | Generates and validates reporting units; `--install` installs/enables them |
| `set-timezone` | Updates workspace/reporting timezone; the timer must then be regenerated |

`run` defaults to `prepare`. Installation requires explicit `--mode install`.
After [initializing a workspace](docs/user-guide.md#initialize-a-workspace):

```bash
python3 ~/thesis/integrated-system/honeypotctl.py run \
  --workspace "$HOME/thesis/honeypot-workspace" --mode install
```

This automates discovery through an immediate report. Users supply the authorized
network and prerequisites. The tool does not install Linux or Kubernetes, keep
rescanning in the background, or automatically remove obsolete releases.
The daily timer runs reporting only. Honeypots keep recording interactions while
their workloads and storage are available; an initial report may correctly be empty.

## Supported operating model

- Linux, Python 3.10+, Helm 3, and the other documented dependencies.
- Current pinned recipes require a Linux **amd64/x86-64** Kubernetes node.
  There is no Ubuntu-version whitelist; live tests used Ubuntu 24.04.
- Run the workflow on its storage node. A remote kubeconfig alone does not give
  the collector access to local database/log files.
- One mixed Cowrie/Dionaea release and one separate Conpot release per workspace,
  selecting the sources supported by discovery.
- Existing cluster, namespace, permissions, and enforced outbound policy.
- Current storage recipes use UID/GID 1000 and mode 0750. Reporting requires the
  appropriate user/group access. See the prerequisite guide for exact checks.

## Verified status

Evidence recorded on **22 September 2026** establishes:

- 26 offline tests passed on `thesis-repro` after the timezone update.
- Live CLI installation, reporting, and a compatible revision-1-to-2 upgrade
  passed on `thesis-repro`; checked persistent state and source identities survived.
- A temporary automatic reporting timer executed successfully. The daily
  `Europe/Athens` timer was installed and its next activation inspected; its first
  automatic execution under that new schedule has not yet been recorded here.
- A fresh `thesis-handoff` VM cloned public commit
  `efcd26d42efeb483bd4a299948548ba58e628540`, installed prerequisites, and completed
  the CLI scan-to-report workflow with a clean integration working tree.
- External HTTP, SSH-banner, and Modbus Read Coils exchanges matched saved server
  records. Policy/REJECT counters supported blocking the tested outbound TCP
  attempts from each of its two honeypot pods.

The fresh-VM exercise was **guided**. An independent person following only the
published instructions remains untested. These results do not establish support
for every Linux distribution, architecture, cluster, or real industrial device.

Detailed records: [workflow validation](docs/workflow-validation.md),
[fresh-VM handoff](docs/handoff-acceptance.md), and the earlier
[staged reproduction](docs/reproduction-guide.md).

## Reporting and operational limits

- SSH/HTTP counts represent incoming connection starts, not confirmed attacks.
- Conpot logged starts are reported separately; session metadata can be reused.
- Controlled-test labels are optional annotations requiring matched evidence.
  Unclassified events are not automatically malicious.
- Reports use supplied snapshots; a requested time window does not establish
  complete collection coverage. Service-port metadata describes collection time.
- Upgrades are sequential across releases, not a transaction. Some topology
  changes are refused and partial failures can require operator recovery.
- A default-deny policy object's presence is not proof of enforcement.

## Repository layout and legacy entry points

`honeypotctl.py` orchestrates `run_system.py`, `prepare_run.py`,
`install_prepared.py` / `deploy_prepared.py`, and `report_config.py`.
The lower-level scripts remain available for inspecting or resuming individual
stages; see the [user guide](docs/user-guide.md#lower-level-and-legacy-commands).

`config/` contains original-lab examples. New users should use `init` to generate
workspace-specific paths, identities, and empty labels. `assets/` contains the
pinned HoneyChart reconstruction inputs and Conpot recipe assets;
`image-pins.yaml` supplies pinned mixed-release images.

`deploy.sh`, earlier versioned pipeline scripts, and checked-in `systemd/` units
are legacy lab entry points/examples. Use the workspace CLI for a new installation.
Do not copy the original lab's controlled-test labels into a new workspace.

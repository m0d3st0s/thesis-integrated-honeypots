# User workflow: prerequisites first, automated honeypot workflow second

## Scope

`honeypotctl.py` is the user-facing command. It configures a private workspace,
checks prerequisites, invokes discovery/profiling/preparation/deployment, derives
reporting configuration from the selected services, and collects an immediate
report. It can also install a daily reporting timer when explicitly requested.

There is no Ubuntu version gate. This implementation requires Linux capabilities,
not a particular distribution. The pinned container recipes have been validated
on Linux amd64 only; the checker rejects other node architectures until their
images/layouts are validated. This is an image-support restriction, not an Ubuntu
restriction. The CLI passed a live install-to-report test on 22 September 2026.
See workflow-validation.md; clean handoff validation remains pending.

## What users prepare

Run as the account that will collect reports, on the Kubernetes node that stores
honeypot data. A remote kubectl client alone is insufficient.

Required prerequisites:

- Linux, Python 3.10+ with SQLite, Bash, `ip`, `sudo`, Nmap with `modbus-discover`.
- Node.js/npm, zip/unzip, the reconstructed HoneyChart checkout and a running
  HoneyChart HTTP service. Follow `reproduction-guide.md` and
  `assets/honeychart/manifest.json`; apply the bundled compatibility patch and use
  the bundled npm lockfile. The HTTP build endpoint must be accessible.
- Helm 3 and kubectl compatible with the installed Kubernetes server; working
  kubeconfig and permissions to manage the honeypot namespace resources, Helm
  releases, and the temporary initialization pods.
- A Ready, schedulable Linux amd64 node with a unique `kubernetes.io/hostname`
  label matching the configured storage node, and functional NetworkPolicy
  enforcement. The controller account must have filesystem access to its logs.
- The current pinned recipes initialize storage with UID/GID 1000 and mode 0750.
  The reporting account therefore needs UID 1000, supplementary group 1000, or
  root access. This is an explicit existing recipe limitation; changing the
  image accounts/storage permissions requires validation. Do not make keys or
  kubeconfig world-readable to work around permissions.
- A pre-created namespace with an all-pod default-deny outbound policy. The checker
  verifies policy configuration, not packet-level enforcement. See the policy
  below and test enforcement for your environment.
- `systemd-analyze` and systemd only if using the optional scheduling command.

Tested versions are recorded in `reproduction-guide.md`. Version output and HTTP
reachability do not establish universal compatibility; chart validation and
runtime checks remain part of every deployment.

No package manager is invoked by this tool. It does not install Linux, Kubernetes,
Node, Helm, or HoneyChart. It never guesses the network you are authorized to scan.
It does not continually rescan or automatically remove a whole obsolete release.

## Namespace prerequisite

Choose a dedicated namespace, for example `honeypots`. Apply this once with your
configured kubectl; substitute the namespace consistently if necessary:

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
  policyTypes: [Egress]
  egress: []
```

Additional egress-allow policies are refused by the new check because their
selectors/union could weaken containment. Review such policies explicitly rather
than treating a default-deny object's presence as proof of isolation.

## 1. Initialize a workspace

The following is a lab example. Substitute your actual authorized network,
interface, local scanner address, node hostname label, and kubeconfig. Release
names below are intentionally distinct from the existing reproduction experiment.
Use dedicated empty storage roots for first installation.

```bash
cd ~/thesis/integrated-system
python3 honeypotctl.py init \
  --workspace "$HOME/thesis/user-workflow" \
  --network 192.168.77.0/24 \
  --interface enp0s8 \
  --scanner-ip 192.168.77.11 \
  --exclude 192.168.77.10 \
  --node-hostname thesis-repro \
  --kubeconfig "$HOME/.kube/thesis-k3s.yaml" \
  --namespace honeypots \
  --mixed-release workflow-mixed \
  --conpot-release workflow-modbus \
  --state-root /var/lib/thesis-honeypots/user-workflow \
  --log-root /var/log/honeypots/user-workflow
```

Initialization does not scan or change the cluster. It refuses to overwrite a
workspace. It creates configuration copies, a unique source identity, empty label
files, and directories for runs and reports. Paths and the current user are not
hard-coded. Scanner exclusions include the scanner itself. Default scan ports are
22, 80, 443, 445, 502, and 1502, with Modbus probes on 502 and 1502; edit `scan.json`
to change authorized scope/ports. Review it before running.

HoneyChart defaults to `http://127.0.0.1:8081/custom_build_endpoint`; use
`--honeychart-endpoint` during initialization to change it. Do not insert credentials
into that URL. Configuration files are private but are included in run evidence.

State roots, log roots, release identities and namespace bind a workspace to its
sources. Changing them requires a new workspace. A new workspace is not automatic
adoption of existing Helm releases or stored data. Keep the workspace identity for
upgrades; never reuse it after resetting/replacing source storage.

## 2. Check prerequisites

```bash
python3 honeypotctl.py check --workspace "$HOME/thesis/user-workflow"
```

This reads tool versions, interface configuration, namespace, node, policy, assets,
and HoneyChart HTTP availability. It performs no scan or cluster mutation. Fix
reported failures before continuing. It is not a complete image-pull, RBAC,
protocol-behavior, storage-access, or firewall-enforcement test; deployment and
reporting errors are still recorded with their stage and log.

## 3. Run the workflow

Start HoneyChart and the authorized targets, then:

```bash
python3 honeypotctl.py run \
  --workspace "$HOME/thesis/user-workflow" --mode install
```

One command now performs prerequisite checks, fresh discovery, profiling and
selection, chart preparation/validation, storage initialization, deployment checks,
reporting configuration publication, and an immediate report. Each run gets a new
`runs/run-*` directory with `workflow.json` and stage logs. The immediate report
covers today at 00:00 UTC through collection initiation; it is a snapshot, not a
claim of full-window coverage. Optionally supply an earlier timezone-aware
`--since` timestamp.

For inspection without deployment:

```bash
python3 honeypotctl.py run --workspace "$HOME/thesis/user-workflow" --mode prepare
```

Default mode is prepare. To rescan and upgrade a successfully installed workspace:

```bash
python3 honeypotctl.py run --workspace "$HOME/thesis/user-workflow" --mode upgrade
```

Upgrade mode deliberately uses the existing conservative deployer. It is not a
universal reconciler: combinations requiring both a newly created release and an
existing release are refused by the underlying preflight rather than partly
installed automatically. Adding a previously absent container may need supported
retained storage; arbitrary new-container bootstrap during upgrade is not provided.
Whole releases no longer selected are retained, not silently uninstalled. The
new report configuration follows the selected releases; retained unselected source
history is available through archived prior configurations. Review changes in
`reporting-proposed.json` and saved request/plan evidence.

No targets leaves an existing deployment/report configuration unchanged. Ambiguous,
incomplete, or unsupported evidence can stop preparation; inspect its stage logs.
No automatic destructive cleanup is performed on failure.

A second install in a successfully deployed workspace is refused. Use upgrade.
If installation partially fails, inspect its evidence before recovery: releases or
storage may already exist. Do not remove data just to get past a refusal.

## 4. Reporting

The published `reporting.json` is generated from successful prepared requests and
uses unique database/log identities derived from the workspace, with stable IDs
across upgrades. It selects only deployed sources. SSH-only, HTTP-only, Modbus-only,
and their combinations are supported. An absent section is explicitly
`not_selected`, not reported as zero. A missing selected source fails the report.
At most one mixed release and one separate Conpot release are supported.

```bash
python3 honeypotctl.py report --workspace "$HOME/thesis/user-workflow" \
  --since 2026-09-22T00:00:00Z --until 2026-09-23T00:00:00Z

python3 honeypotctl.py report --workspace "$HOME/thesis/user-workflow" --previous-day
```

Add `--output /new/directory` to choose an output; otherwise a unique report folder
is created under the workspace. HoneyChart and Nmap are not needed for reporting.

Interactions are initially unclassified. Controlled-test labels are optional
research annotations, not an operational prerequisite. Only label events after
matching independent client and server evidence. Never import the old lab's
numeric database labels into a new source identity.

If reporting fails after deployment, `workflow.json` retains
`deployment_status: completed`, and the active configuration remains available.
Fix source access and use `report`; do not rerun install. Prior configurations are
preserved in upgrade run directories. Missing sources are never treated as empty.

Conpot logged starts are separate from SSH/HTTP incoming connection counts.
Unclassified does not mean malicious; tests do not establish attacker preferences.
The existing coverage, timestamp, rotation, and external-port attribution
limitations still apply.

## 5. Optional daily reporting

Generate and validate units without installing them:

```bash
python3 honeypotctl.py schedule --workspace "$HOME/thesis/user-workflow" \
  --output "$HOME/thesis/report-units-user-workflow" --utc-time 00:10
```

To install and enable them, use a new output directory and add `--install`:

```bash
python3 honeypotctl.py schedule --workspace "$HOME/thesis/user-workflow" \
  --output "$HOME/thesis/report-units-user-workflow-installed" \
  --utc-time 00:10 --install
```

This invokes sudo for installing system units and enabling the timer. Unit names
include a workspace identity prefix, so the old thesis timer is not replaced.
Same-name existing units are backed up in the workspace's runs directory. It does
not start an extra manual report, though a persistent timer can trigger a catch-up.
Inspect the generated unit and `systemctl list-timers --all --no-pager`.

Generated services call `honeypotctl.py report`, share its workspace lock, and use
the actual account and Python executable. Keep the project and workspace at their
configured paths. A scheduled report fails visibly if another operation holds the
lock; it does not wait indefinitely or race a deployment. Direct legacy commands
do not share this workspace lock—do not run them concurrently against these releases.
Persistent timers do not backfill every missed day. Verify the first automatic
execution separately from a manual service test.

## Failure records and scope of automation

Read the reported run directory and stage log. A failure after some release
operations is not a transactional rollback. The tool does not guess a recovery
that would delete persistent state, change source identities, or weaken policy.
Reporting sources are published only after deployment checks pass; a failed
upgrade may leave partial live changes, which require operator inspection before
using the previous report configuration.

Do not change the cluster targeted by a workspace's kubeconfig after installation.
Use a new workspace for another cluster. The current check validates local node
addresses, not a durable cryptographic cluster identity.

## Developer verification and remaining acceptance test

Run the offline suite:

```bash
python3 -m unittest discover -s tests -v
```

Tests exercise real report collectors with SQLite/log fixtures and fake Kubernetes
metadata for all seven nonempty service selections; missing/malformed selected
sources; configuration/identity guards and locking; simulated orchestrator stage
success/failure, no-target preservation, and report failure after deployment.
They do not run Nmap scans, pull images, deploy containers, or prove network policy
behavior. The new CLI must pass a live run and a clean handoff before claiming the
whole new user workflow is validated. Historical reproduction results in
`reproduction-guide.md` refer to the earlier staged commands, not this new CLI.
